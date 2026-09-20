#pragma once
// handler_concept.hpp
//
// Contrats (concepts C++20) que doit respecter un handler applicatif,
// verifies A LA COMPILATION (pas de vtable / pas d'interface virtuelle :
// dispatch entierement statique, zero cout par paquet a l'execution).

#include <concepts>
#include <cstddef>
#include <span>

#include "protocol.hpp"
#include "session.hpp"

namespace netsrv {

// Handler pour un protocole "connecte" (TCP) : cycle de vie complet.
// Le `&& Protocol::connection_oriented` est important : grace au
// court-circuit des conjonctions de contraintes en C++20, il empeche le
// compilateur de meme essayer de nommer Session<Protocol, H> (qui exige
// Protocol::connection_oriented) quand Protocol est UDP.
template <typename H, typename Protocol>
concept StreamHandler =
    SocketProtocol<Protocol> && Protocol::connection_oriented &&
    requires(H& h, Session<Protocol, H>& session, std::span<const std::byte> payload) {
        { h.on_connect(session) }          -> std::same_as<asio::awaitable<void>>;
        { h.on_message(session, payload) } -> std::same_as<asio::awaitable<void>>;
        { h.on_disconnect(session) }       -> std::same_as<void>;
    };

// Handler pour un protocole "sans connexion" (UDP) : un seul point d'entree,
// appele pour chaque datagramme recu (avec son endpoint source).
template <typename H, typename Protocol>
concept DatagramHandler =
    SocketProtocol<Protocol> && !Protocol::connection_oriented &&
    requires(H& h, typename Protocol::socket_type& socket,
             const typename Protocol::endpoint_type& from,
             std::span<const std::byte> payload) {
        { h.on_datagram(socket, from, payload) } -> std::same_as<asio::awaitable<void>>;
    };

// Selectionne automatiquement le bon contrat selon le protocole : c'est ce
// concept que Server<Protocol, Role, Handler> exige de son 3e parametre.
template <typename H, typename Protocol>
concept CompatibleHandler = StreamHandler<H, Protocol> || DatagramHandler<H, Protocol>;

} // namespace netsrv
