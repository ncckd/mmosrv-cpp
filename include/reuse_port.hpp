#pragma once
// reuse_port.hpp
//
// Option socket SO_REUSEPORT portable (Linux / *BSD / macOS) pour Asio.
// Permet a plusieurs sockets (une par thread/coeur) de se binder sur le
// MEME port : c'est alors le noyau qui repartit les connexions/datagrammes
// entrants entre elles, sans acceptor central ni verrou applicatif de
// repartition. C'est la base du design "thread-per-core" de server.hpp.

#include <asio.hpp>
#include <cstddef>

#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
    #include <sys/socket.h>
    #define NETSRV_HAS_REUSEPORT 1
#else
    #define NETSRV_HAS_REUSEPORT 0
#endif

namespace netsrv {

#if NETSRV_HAS_REUSEPORT
// Asio ne fournit pas d'enveloppe portable pour SO_REUSEPORT (contrairement
// a SO_REUSEADDR). On la definit nous-memes au format attendu par
// basic_socket::set_option (cf. doc Asio "Custom Socket Options").
class reuse_port {
public:
    explicit reuse_port(bool enabled = true) noexcept : value_(enabled ? 1 : 0) {}

    template <typename Protocol>
    int level(const Protocol&) const noexcept { return SOL_SOCKET; }

    template <typename Protocol>
    int name(const Protocol&) const noexcept { return SO_REUSEPORT; }

    template <typename Protocol>
    int* data(const Protocol&) noexcept { return &value_; }

    template <typename Protocol>
    const int* data(const Protocol&) const noexcept { return &value_; }

    template <typename Protocol>
    std::size_t size(const Protocol&) const noexcept { return sizeof(value_); }

private:
    int value_;
};
#endif

// Active SO_REUSEADDR (+ SO_REUSEPORT si disponible) sur un socket/acceptor
// deja ouvert (open() doit avoir ete appele avant). No-op silencieux sur les
// plateformes sans SO_REUSEPORT (Windows notamment) : voir le README pour
// le repli a prevoir dans ce cas (acceptor unique + repartition logicielle).
template <typename SocketOrAcceptor>
void enable_port_sharing(SocketOrAcceptor& s) {
    asio::error_code ec;
    s.set_option(asio::socket_base::reuse_address(true), ec);
#if NETSRV_HAS_REUSEPORT
    s.set_option(reuse_port(true), ec);
#endif
}

} // namespace netsrv
