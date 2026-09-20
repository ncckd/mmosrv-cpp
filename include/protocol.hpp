#pragma once
// protocol.hpp
//
// Premier parametre template du framework : le PROTOCOLE (TCP ou UDP),
// exprime comme une politique ("policy") contrainte par un concept C++20.
// Aucune vtable, aucun branchement runtime : le choix TCP/UDP est resolu
// entierement a la compilation.

#include <asio.hpp>
#include <concepts>
#include <string_view>

namespace netsrv {

// Ce que doit fournir une politique de protocole pour etre utilisable par
// Server<Protocol, Role, Handler> (voir server.hpp) et Session (session.hpp).
template <typename P>
concept SocketProtocol = requires {
    typename P::socket_type;
    typename P::endpoint_type;
    { P::connection_oriented } -> std::convertible_to<bool>;
    { P::name() }              -> std::convertible_to<std::string_view>;
};

struct TcpProtocol {
    using socket_type   = asio::ip::tcp::socket;
    using acceptor_type = asio::ip::tcp::acceptor;
    using endpoint_type = asio::ip::tcp::endpoint;

    static constexpr bool connection_oriented = true;
    static constexpr std::string_view name() noexcept { return "TCP"; }
};

struct UdpProtocol {
    using socket_type   = asio::ip::udp::socket;
    using endpoint_type = asio::ip::udp::endpoint;
    // Pas d'acceptor_type : l'UDP n'a pas de notion de connexion/ecoute.
    // (voir server.hpp pour la raison pour laquelle ce n'est pas un probleme
    // vis-a-vis de l'instanciation du template en mode UDP)

    static constexpr bool connection_oriented = false;
    static constexpr std::string_view name() noexcept { return "UDP"; }
};

static_assert(SocketProtocol<TcpProtocol>);
static_assert(SocketProtocol<UdpProtocol>);

} // namespace netsrv
