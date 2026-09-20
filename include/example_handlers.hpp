#pragma once
// example_handlers.hpp
//
// Historique : Master/Login/World(TCP) vivent desormais dans
// handlers/master_handler.hpp, login_handler.hpp, world_handler.hpp (avec
// la gestion du hop client par jetons). Ce fichier ne garde que
// WorldUdpHandler, pour lequel il n'y a pas encore de contrepartie dediee.
//
// IMPORTANT : un meme Handler est PARTAGE par tous les threads I/O. Tout
// etat mutable partage entre sessions/datagrammes doit etre thread-safe.

#include <asio.hpp>

#include <cstddef>
#include <span>

#include "protocol.hpp"

namespace netsrv::examples {

// World (UDP) : exemple de flux temps-reel complementaire (positions,
// telemetry...). Montre que le MEME Server<> s'utilise avec l'autre
// protocole en changeant uniquement le 1er argument template.
class WorldUdpHandler {
public:
    asio::awaitable<void> on_datagram(asio::ip::udp::socket& socket,
                                       const asio::ip::udp::endpoint& from,
                                       std::span<const std::byte> payload) {
        // TODO: decoder le paquet (ex: snapshot de position) et mettre a
        // jour l'etat du monde. ATTENTION : appelee concurremment depuis
        // N threads (un par coeur) -- l'etat partage doit etre thread-safe
        // ou shardee (ex: par grille spatiale / par entite).
        co_await socket.async_send_to(asio::buffer(payload.data(), payload.size()), from,
                                       asio::as_tuple(asio::use_awaitable));
    }
};

} // namespace netsrv::examples
