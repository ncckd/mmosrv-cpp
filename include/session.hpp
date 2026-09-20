#pragma once
// session.hpp
//
// Session TCP : le cycle de vie complet d'une connexion, exprime comme UNE
// coroutine C++20 (asio::awaitable<void>). Cette coroutine s'execute
// integralement sur le thread qui a accepte la connexion (design
// "shared-nothing" par coeur, voir server.hpp) : aucune synchronisation
// (mutex/atomic) n'est necessaire sur le chemin chaud d'UNE session.
//
// Framing applicatif : prefixe de longueur 4 octets (big-endian) + payload.
// Remplacez par votre propre en-tete de paquet (opcode, checksum, version...)
// si besoin ; la mecanique de lecture/ecriture partielle reste identique.

#include <asio.hpp>
#include <asio/experimental/awaitable_operators.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <memory_resource>
#include <optional>
#include <span>
#include <variant>
#include <vector>

#include "net/framing.hpp"
#include "protocol.hpp"

namespace netsrv {

using namespace asio::experimental::awaitable_operators;

template <SocketProtocol Protocol, typename Handler>
    requires Protocol::connection_oriented
class Session {
public:
    using socket_type   = typename Protocol::socket_type;
    using endpoint_type = typename Protocol::endpoint_type;

    Session(socket_type socket,
            std::shared_ptr<Handler> handler,
            std::pmr::memory_resource* arena,
            std::size_t max_frame_bytes,
            std::chrono::steady_clock::duration idle_timeout)
        : socket_(std::move(socket))
        , handler_(std::move(handler))
        , idle_timer_(socket_.get_executor())
        , max_frame_bytes_(max_frame_bytes)
        , idle_timeout_(idle_timeout)
        , buffer_(arena)
    {
        asio::error_code ec;
        remote_ = socket_.remote_endpoint(ec);
        // Si ec est positionne (le pair est deja parti), remote_ reste par
        // defaut : sans consequence, la premiere lecture echouera et run()
        // fermera la session proprement plus bas.
        buffer_.resize(max_frame_bytes_);
    }

    // Boucle de vie complete de la session. Un handler applicatif PEUT
    // lever une exception (ex: un appel reseau interne qui echoue, cf.
    // store/store_client.hpp) : le try/catch ci-dessous garantit qu'une
    // session en echec ferme proprement SA connexion sans jamais faire
    // planter le process entier (une exception non rattrapee qui
    // s'echappe d'une coroutine co_spawn-ee en `detached` provoque un
    // std::terminate() -- comportement documente d'Asio). C'est le
    // framework qui porte cette garantie une fois pour toutes, plutot que
    // d'exiger que chaque Handler s'en souvienne.
    asio::awaitable<void> run() {
        try {
            co_await handler_->on_connect(*this);

            for (;;) {
                idle_timer_.expires_after(idle_timeout_);

                // Course "lire une trame" vs "timeout d'inactivite" : technique
                // idiomatique de asio::experimental::awaitable_operators (C++20)
                // pour eviter un timer/watchdog dedie par connexion. L'operation
                // perdante est automatiquement annulee par Asio.
                auto result = co_await (read_frame() || wait_idle());

                if (result.index() == 1) break;              // le timeout a gagne
                auto& payload_opt = std::get<0>(result);
                if (!payload_opt) break;                       // erreur / EOF en lecture

                co_await handler_->on_message(*this, *payload_opt);
            }
        } catch (const std::exception&) {
            // Session terminee proprement ; les autres sessions/threads
            // continuent sans etre affectes.
        }

        handler_->on_disconnect(*this);
        close();
    }

    asio::awaitable<void> send(std::span<const std::byte> payload) {
        std::array<std::byte, kFrameHeaderSize> header{};
        const std::uint32_t be_len = to_network(static_cast<std::uint32_t>(payload.size()));
        std::memcpy(header.data(), &be_len, kFrameHeaderSize);

        std::array<asio::const_buffer, 2> buffers{
            asio::buffer(header.data(), header.size()),
            asio::buffer(payload.data(), payload.size())
        };

        auto [ec, n] = co_await asio::async_write(
            socket_, buffers, asio::as_tuple(asio::use_awaitable));
        if (ec) close();
    }

    const endpoint_type& remote_endpoint() const noexcept { return remote_; }
    void close() { asio::error_code ignored; socket_.close(ignored); }

private:
    asio::awaitable<std::monostate> wait_idle() {
        co_await idle_timer_.async_wait(asio::as_tuple(asio::use_awaitable));
        co_return std::monostate{};
    }

    asio::awaitable<std::optional<std::span<const std::byte>>> read_frame() {
        auto [ec1, n1] = co_await asio::async_read(
            socket_, asio::buffer(header_buf_), asio::as_tuple(asio::use_awaitable));
        if (ec1 || n1 != kFrameHeaderSize) co_return std::nullopt;

        std::uint32_t len_be{};
        std::memcpy(&len_be, header_buf_.data(), kFrameHeaderSize);
        const std::uint32_t len = from_network(len_be);
        if (len == 0 || len > max_frame_bytes_) co_return std::nullopt; // trame invalide

        auto [ec2, n2] = co_await asio::async_read(
            socket_, asio::buffer(buffer_.data(), len), asio::as_tuple(asio::use_awaitable));
        if (ec2 || n2 != len) co_return std::nullopt;

        co_return std::span<const std::byte>{buffer_.data(), len};
    }

    socket_type socket_;
    std::shared_ptr<Handler> handler_;
    asio::steady_timer idle_timer_;
    std::size_t max_frame_bytes_;
    std::chrono::steady_clock::duration idle_timeout_;
    endpoint_type remote_{};
    std::array<std::byte, kFrameHeaderSize> header_buf_{};
    std::pmr::vector<std::byte> buffer_; // alloue depuis l'arena pmr du thread proprietaire
};

} // namespace netsrv
