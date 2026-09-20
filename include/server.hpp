#pragma once
// server.hpp
//
// Server<Protocol, Role, Handler> : coeur du framework.
//
// Architecture "thread-per-core / shared-nothing" pour des milliers de
// connexions simultanees :
//
//   - N threads (std::jthread), N = ServerConfig<Role>::io_threads, ou
//     hardware_concurrency() si 0.
//   - Chaque thread possede SON PROPRE asio::io_context ET sa propre socket
//     d'ecoute, bindee sur le MEME port grace a SO_REUSEPORT : c'est le
//     noyau qui repartit les connexions/paquets entrants entre les threads,
//     sans acceptor central ni verrou de repartition applicatif.
//   - Chaque session (coroutine C++20) vit entierement sur le thread qui
//     l'a acceptee : zero synchronisation sur le chemin chaud d'une session.
//   - Arret gracieux : on ferme l'acceptor/la socket et les sessions en
//     cours (ce qui les fait echouer proprement a leur prochaine lecture),
//     puis on laisse io_context::run() se vider naturellement. On n'appelle
//     JAMAIS io_context::stop() de force, ce qui abandonnerait des
//     coroutines en plein vol.
//
// NOTE PORTABILITE : SO_REUSEPORT n'existe pas sur Windows. Sur cette
// plateforme, enable_port_sharing() est un no-op : un seul thread "gagnera"
// le bind, les autres echoueront silencieusement leur bind() (a corriger si
// vous ciblez Windows -- cf. README, piste : acceptor unique + repartition
// des sockets acceptees vers les workers via asio::post).

#include <asio.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <concepts>
#include <cstddef>
#include <format>
#include <iostream>
#include <memory>
#include <memory_resource>
#include <span>
#include <stop_token>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include "handler_concept.hpp"
#include "protocol.hpp"
#include "reuse_port.hpp"
#include "server_role.hpp"
#include "session.hpp"

#if defined(__linux__)
#include <pthread.h>
#endif

namespace netsrv {

// Registre des sessions vivantes sur UN thread I/O donne. N'est jamais
// touche que par le thread proprietaire : le stop_callback de server.hpp
// passe par asio::post() pour garantir cela, meme si request_stop() est
// appele depuis un autre thread (typiquement le thread principal).
template <typename SessionT>
class SessionRegistry {
public:
    void add(const std::shared_ptr<SessionT>& s) { sessions_.insert(s); }
    void remove(const std::shared_ptr<SessionT>& s) { sessions_.erase(s); }
    void close_all() { for (auto& s : sessions_) s->close(); }

private:
    std::unordered_set<std::shared_ptr<SessionT>> sessions_;
};

template <SocketProtocol Protocol, ServerRole Role, typename Handler>
    requires CompatibleHandler<Handler, Protocol>
class Server {
public:
    using Config        = ServerConfig<Role>;
    using socket_type    = typename Protocol::socket_type;
    using endpoint_type  = typename Protocol::endpoint_type;

    Server(std::shared_ptr<Handler> handler, unsigned short port,
           std::string bind_address = "0.0.0.0")
        : handler_(std::move(handler))
        , port_(port)
        , bind_address_(std::move(bind_address))
        , thread_count_(Config::io_threads != 0
                             ? Config::io_threads
                             : std::max(1u, std::thread::hardware_concurrency()))
    {
        workers_.reserve(thread_count_);
    }

    ~Server() { stop(); }

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    // Demarre les threads I/O. Non bloquant.
    void start() {
        std::cout << std::format(
            "[{}] demarrage sur {}:{} ({} thread(s), {} conn. max, protocole {})\n",
            to_string(Role), bind_address_, port_, thread_count_,
            Config::max_connections, Protocol::name());

        for (std::size_t i = 0; i < thread_count_; ++i) {
            workers_.emplace_back([this, i](std::stop_token stoken) {
                pin_to_core(i);
                run_worker(stoken);
            });
        }
    }

    // Arret gracieux et BLOQUANT : demande l'arret a chaque thread (ce qui
    // ferme l'ecoute + les sessions en cours), puis attend que chaque
    // io_context ait naturellement fini de se vider avant de rendre la main.
    void stop() {
        for (auto& w : workers_) w.request_stop();
        for (auto& w : workers_) if (w.joinable()) w.join();
    }

    // Attend (avec timeout) que le nombre de connexions actives retombe a
    // zero, SANS arreter le serveur. Utile pour une fenetre de maintenance.
    // Repose sur std::atomic::wait/notify (C++20) : pas de polling actif.
    void wait_drained(std::chrono::milliseconds timeout = std::chrono::seconds(30)) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        std::size_t current;
        while ((current = active_connections_.load(std::memory_order_acquire)) != 0) {
            if (std::chrono::steady_clock::now() >= deadline) return;
            active_connections_.wait(current);
        }
    }

    std::size_t active_connections() const noexcept {
        return active_connections_.load(std::memory_order_relaxed);
    }

private:
    void pin_to_core([[maybe_unused]] std::size_t index) {
#if defined(__linux__)
        const auto n = std::thread::hardware_concurrency();
        if (n == 0) return;
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(index % n, &cpuset);
        pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
#endif
        // Autres plateformes : on laisse l'OS scheduler decider. L'affinite
        // CPU est une optimisation (cache locality, moins de migrations),
        // pas une necessite fonctionnelle.
    }

    void run_worker(std::stop_token stoken) {
        try {
            run_worker_impl(stoken);
        } catch (const std::exception& e) {
            // Un thread I/O qui plante ne doit pas emporter tout le process
            // (une exception non rattrapee ici -> std::terminate()).
            std::cerr << std::format("[{}] erreur fatale sur un thread I/O: {}\n",
                                      to_string(Role), e.what());
        }
    }

    void run_worker_impl(std::stop_token stoken) {
        // Declaree AVANT io_context : garantit sa destruction APRES lui
        // (ordre inverse de construction), donc apres que toute session
        // ayant alloue depuis cette arena ait deja ete detruite.
        std::pmr::unsynchronized_pool_resource arena;
        asio::io_context io_context(1); // hint "1 thread" -> Asio evite le
                                         // verrouillage interne de sa file

        if constexpr (Protocol::connection_oriented) {
            typename Protocol::acceptor_type acceptor(io_context);
            SessionRegistry<Session<Protocol, Handler>> registry;

            std::stop_callback on_stop(stoken, [&] {
                // request_stop() peut etre appele depuis un AUTRE thread :
                // asio::post() garantit que la fermeture s'execute bien sur
                // le thread proprietaire de l'acceptor / des sessions.
                asio::post(io_context, [&] {
                    asio::error_code ignored;
                    acceptor.close(ignored);
                    registry.close_all();
                });
            });

            asio::co_spawn(io_context,
                            accept_loop(io_context, acceptor, registry, arena),
                            asio::detached);
            io_context.run(); // revient tout seul, une fois vraiment inactif
        } else {
            socket_type socket(io_context);

            std::stop_callback on_stop(stoken, [&] {
                asio::post(io_context, [&] {
                    asio::error_code ignored;
                    socket.close(ignored);
                });
            });

            asio::co_spawn(io_context, datagram_loop(io_context, socket, arena),
                            asio::detached);
            io_context.run();
        }
    }

    // Fonction-GABARIT (P=Protocol par defaut), volontairement : accept_loop
    // reference `typename Protocol::acceptor_type`, qui n'existe PAS pour
    // UdpProtocol. Si c'etait une fonction membre ORDINAIRE, sa DECLARATION
    // serait instanciee avec la classe Server (meme jamais appelee) et
    // casserait la compilation de Server<UdpProtocol, ...>. En un gabarit,
    // la resolution du type est differee jusqu'au premier appel reel --
    // qui n'arrive jamais en UDP grace au `if constexpr` ci-dessus.
    template <typename P = Protocol>
    asio::awaitable<void> accept_loop(asio::io_context& io_context,
                                       typename P::acceptor_type& acceptor,
                                       SessionRegistry<Session<P, Handler>>& registry,
                                       std::pmr::memory_resource& arena) {
        static_assert(std::same_as<P, Protocol>);

        typename P::endpoint_type endpoint(asio::ip::make_address(bind_address_), port_);
        acceptor.open(endpoint.protocol());
        netsrv::enable_port_sharing(acceptor);
        acceptor.bind(endpoint);
        acceptor.listen(asio::socket_base::max_listen_connections);

        for (;;) {
            auto [ec, socket] = co_await acceptor.async_accept(
                asio::as_tuple(asio::use_awaitable));
            if (ec) {
                if (ec != asio::error::operation_aborted)
                    std::cerr << std::format("[{}] erreur accept: {}\n",
                                              to_string(Role), ec.message());
                co_return;
            }

            if (active_connections_.load(std::memory_order_relaxed) >= Config::max_connections) {
                asio::error_code ignored;
                socket.close(ignored); // backpressure : refuser plutot que saturer
                continue;
            }

            asio::error_code opt_ec;
            socket.set_option(asio::ip::tcp::no_delay(true), opt_ec); // Nagle off

            on_connection_opened();
            auto session = std::make_shared<Session<P, Handler>>(
                std::move(socket), handler_, &arena,
                Config::read_buffer_bytes, Config::idle_timeout);
            registry.add(session);

            asio::co_spawn(io_context,
                [this, session, &registry]() -> asio::awaitable<void> {
                    co_await session->run();
                    registry.remove(session);
                    on_connection_closed();
                },
                asio::detached);
        }
    }

    asio::awaitable<void> datagram_loop(asio::io_context&, socket_type& socket,
                                         std::pmr::memory_resource&) {
        endpoint_type endpoint(asio::ip::make_address(bind_address_), port_);
        socket.open(endpoint.protocol());
        netsrv::enable_port_sharing(socket);
        socket.bind(endpoint);

        std::vector<std::byte> buffer(Config::read_buffer_bytes);
        endpoint_type sender;

        for (;;) {
            auto [ec, n] = co_await socket.async_receive_from(
                asio::buffer(buffer), sender, asio::as_tuple(asio::use_awaitable));
            if (ec) {
                if (ec != asio::error::operation_aborted)
                    std::cerr << std::format("[{}] erreur recv: {}\n",
                                              to_string(Role), ec.message());
                co_return;
            }
            co_await handler_->on_datagram(
                socket, sender, std::span<const std::byte>(buffer.data(), n));
        }
    }

    void on_connection_opened() {
        active_connections_.fetch_add(1, std::memory_order_relaxed);
    }
    void on_connection_closed() {
        if (active_connections_.fetch_sub(1, std::memory_order_acq_rel) == 1)
            active_connections_.notify_all(); // reveille wait_drained()
    }

    std::shared_ptr<Handler> handler_;
    unsigned short port_;
    std::string bind_address_;
    std::size_t thread_count_;
    std::vector<std::jthread> workers_;
    std::atomic<std::size_t> active_connections_{0};
};

} // namespace netsrv
