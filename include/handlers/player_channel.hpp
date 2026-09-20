#pragma once
// player_channel.hpp
//
// Demonstration directe du pattern que vous avez montre
// (m_handlers[OPCODE] = &Class::fn), reecrit sur le mixin Channel<>
// (net/channel.hpp) qui corrige la race condition d'initialisation.
// Utilise par WorldHandler (handlers/world_handler.hpp) pour tout message
// APRES le hop d'authentification (jeton de session deja verifie).

#include <asio.hpp>

#include <cstdint>
#include <span>

#include "net/channel.hpp"
#include "protocol.hpp"
#include "session.hpp"

namespace netsrv::examples {

class WorldHandler; // definition complete dans world_handler.hpp ; une
                     // forward-decl suffit ici (voir commentaire plus bas
                     // sur pourquoi Session<TcpProtocol, WorldHandler> n'a
                     // pas besoin de WorldHandler complet a ce stade).

namespace opcodes {
    inline constexpr std::uint16_t CPLAYER_PONG   = 0x0001;
    inline constexpr std::uint16_t CPLAYER_MOVE   = 0x0002;
    inline constexpr std::uint16_t CPLAYER_PORTAL = 0x0003;
}

class PlayerChannel : public Channel<PlayerChannel, Session<TcpProtocol, WorldHandler>> {
public:
    using SessionT = Session<TcpProtocol, WorldHandler>;

    asio::awaitable<void> pong(SessionT&, std::span<const std::byte>) {
        // TODO: mettre a jour le timestamp de dernier heartbeat du joueur.
        co_return;
    }

    asio::awaitable<void> move_operation(SessionT& session, std::span<const std::byte> body) {
        // TODO: valider + appliquer le mouvement, diffuser aux joueurs proches.
        co_await session.send(body); // echo par defaut, pour demontrer le flux
    }

    asio::awaitable<void> use_portal(SessionT& session, std::span<const std::byte> body) {
        // TODO: verifier la destination, changer d'instance/zone.
        co_await session.send(body);
    }

    // Appelee UNE fois (magic static dans Channel::handlers()), quel que
    // soit le nombre de threads qui appellent dispatch() juste apres --
    // c'est le correctif direct de votre pattern d'origine.
    static HandlerMap build_handlers() {
        return {
            { opcodes::CPLAYER_PONG,   &PlayerChannel::pong },
            { opcodes::CPLAYER_MOVE,   &PlayerChannel::move_operation },
            { opcodes::CPLAYER_PORTAL, &PlayerChannel::use_portal },
        };
    }
};

} // namespace netsrv::examples
