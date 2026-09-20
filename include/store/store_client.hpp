#pragma once
// store_client.hpp
//
// Client RPC vers le magasin partage (Master), utilise par Login et World
// (processus separes -> passage obligatoire par le reseau, contrairement
// a Master qui y accede directement en memoire, cf. handlers/master_handler.hpp).
//
// Une connexion COURTE par appel (connect -> requete -> reponse -> close)
// plutot qu'une connexion persistante partagee : a la frequence de ces
// appels (une poignee par connexion CLIENT, pas par paquet de gameplay),
// le cout d'un handshake TCP est negligeable face a la simplicite
// gagnee -- pas de multiplexage a gerer entre les N threads d'un meme
// process Login/World qui voudraient utiliser le meme socket en meme temps.
// A la frequence d'un vrai hot-path interne, un pool de connexions par
// thread serait l'evolution naturelle.

#include <asio.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "net/framing.hpp"
#include "store/store_wire.hpp"

namespace netsrv::store {

class StoreClient {
public:
    StoreClient(asio::any_io_executor exec, std::string host, unsigned short port,
                std::vector<std::byte> hmac_key)
        : exec_(std::move(exec)), host_(std::move(host)), port_(port), hmac_key_(std::move(hmac_key)) {}

    asio::awaitable<bool> put(std::string_view key, std::span<const std::byte> value,
                               std::chrono::seconds ttl) {
        auto req = encode_put(hmac_key_, key, value, static_cast<std::uint32_t>(ttl.count()));
        auto resp = co_await roundtrip(req);
        co_return resp && resp->op == Op::Ok;
    }

    asio::awaitable<std::optional<std::vector<std::byte>>> get(std::string_view key) {
        co_return co_await get_or_take(Op::Get, key);
    }

    // "Take" = lecture + suppression atomique cote serveur : c'est ce qui
    // rend un ticket/jeton a usage unique (voir README, section securite).
    asio::awaitable<std::optional<std::vector<std::byte>>> take(std::string_view key) {
        co_return co_await get_or_take(Op::Take, key);
    }

    asio::awaitable<std::vector<Entry>> list_prefix(std::string_view prefix) {
        auto req = encode_list_prefix(hmac_key_, prefix);
        auto resp = co_await roundtrip(req);
        if (!resp || resp->op != Op::List) co_return std::vector<Entry>{};
        co_return resp->entries;
    }

private:
    asio::awaitable<std::optional<std::vector<std::byte>>> get_or_take(Op op, std::string_view key) {
        auto req = encode_get_or_take(op, hmac_key_, key);
        auto resp = co_await roundtrip(req);
        if (!resp || resp->op != Op::Value) co_return std::nullopt;
        co_return resp->value;
    }

    // Erreur reseau/protocole => nullopt, JAMAIS d'exception : "le
    // magasin est injoignable" est un cas attendu (Master en cours de
    // redemarrage), pas exceptionnel, pour un client.
    asio::awaitable<std::optional<Decoded>> roundtrip(const std::vector<std::byte>& request) {
        asio::ip::tcp::resolver resolver(exec_);
        auto [rec_ec, endpoints] = co_await resolver.async_resolve(
            host_, std::to_string(port_), asio::as_tuple(asio::use_awaitable));
        if (rec_ec) co_return std::nullopt;

        asio::ip::tcp::socket socket(exec_);
        auto [conn_ec, used_ep] = co_await asio::async_connect(
            socket, endpoints, asio::as_tuple(asio::use_awaitable));
        if (conn_ec) co_return std::nullopt;

        std::array<std::byte, kFrameHeaderSize> out_header{};
        const std::uint32_t be_len = to_network(static_cast<std::uint32_t>(request.size()));
        std::memcpy(out_header.data(), &be_len, kFrameHeaderSize);
        std::array<asio::const_buffer, 2> out_bufs{
            asio::buffer(out_header.data(), out_header.size()),
            asio::buffer(request.data(), request.size())
        };
        auto [w_ec, w_n] = co_await asio::async_write(socket, out_bufs, asio::as_tuple(asio::use_awaitable));
        if (w_ec) co_return std::nullopt;

        std::array<std::byte, kFrameHeaderSize> in_header{};
        auto [rh_ec, rh_n] = co_await asio::async_read(
            socket, asio::buffer(in_header), asio::as_tuple(asio::use_awaitable));
        if (rh_ec || rh_n != kFrameHeaderSize) co_return std::nullopt;

        std::uint32_t len_be{};
        std::memcpy(&len_be, in_header.data(), kFrameHeaderSize);
        const std::uint32_t len = from_network(len_be);
        if (len == 0 || len > kMaxResponseBytes) co_return std::nullopt;

        std::vector<std::byte> body(len);
        auto [rb_ec, rb_n] = co_await asio::async_read(
            socket, asio::buffer(body), asio::as_tuple(asio::use_awaitable));
        if (rb_ec || rb_n != len) co_return std::nullopt;

        asio::error_code ignored;
        socket.close(ignored);

        co_return decode_and_verify(hmac_key_, body);
    }

    static constexpr std::size_t kMaxResponseBytes = 1 << 20; // 1 Mo, tres large pour ce protocole

    asio::any_io_executor exec_;
    std::string host_;
    unsigned short port_;
    std::vector<std::byte> hmac_key_;
};

} // namespace netsrv::store
