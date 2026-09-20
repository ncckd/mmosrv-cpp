#pragma once
// world_handler.hpp
//
// 1er message du client = jeton de session emis par Login (login_handler.hpp).
// World le "take" aupres du magasin partage : une fois consomme, il ne
// peut plus etre rejoue, meme par une 2e connexion qui l'aurait intercepte.
//
// Les messages SUIVANTS de la meme session sont du gameplay, disperses par
// opcode via PlayerChannel (handlers/player_channel.hpp) -- c'est la
// partie qui repond a votre exemple m_handlers[OPCODE] = &Class::fn.
//
// Etat par session (authentifie ou non) : stocke dans une map THREAD_LOCAL
// plutot que dans une map partagee + mutex. C'est correct PARCE QUE
// l'architecture est shared-nothing (server.hpp) : une session donnee ne
// s'execute jamais que sur UN seul thread du debut a la fin, donc la map
// thread_local de CE thread est la seule jamais consultee ou modifiee pour
// cette session -- zero contention, zero verrou.

#include <asio.hpp>

#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <unordered_map>

#include "handlers/player_channel.hpp"
#include "protocol.hpp"
#include "session.hpp"
#include "store/store_client.hpp"

namespace netsrv::examples {

class WorldHandler {
public:
    using SessionT = Session<TcpProtocol, WorldHandler>;

    explicit WorldHandler(std::shared_ptr<store::StoreClient> store_client)
        : store_client_(std::move(store_client)) {}

    asio::awaitable<void> on_connect(SessionT&) { co_return; }

    asio::awaitable<void> on_message(SessionT& session, std::span<const std::byte> payload) {
        auto& ctx = session_state()[&session];

        if (!ctx.authenticated) {
            const std::string token(reinterpret_cast<const char*>(payload.data()), payload.size());
            auto found = co_await store_client_->take(token);
            if (!found) { session.close(); co_return; } // jeton invalide/expire/deja utilise
            ctx.authenticated = true;
            ctx.username = std::string(reinterpret_cast<const char*>(found->data()), found->size());
            co_return;
        }

        if (payload.size() < 2) co_return; // pas d'opcode : paquet invalide, ignore
        std::uint16_t opcode{};
        std::memcpy(&opcode, payload.data(), 2);
        co_await player_channel_.dispatch(session, opcode, payload.subspan(2));
    }

    // Le meme WorldHandler (et son PlayerChannel) est PARTAGE par tous les
    // threads I/O -- mais PlayerChannel::dispatch() ne fait que lire sa
    // table d'opcodes (magic static, jamais modifiee apres coup), donc
    // aucun etat mutable de WorldHandler lui-meme n'est touche ici : pas
    // de synchronisation necessaire pour ce membre.
    void on_disconnect(SessionT& session) {
        session_state().erase(&session);
    }

private:
    struct SessionState { bool authenticated = false; std::string username; };

    static std::unordered_map<SessionT*, SessionState>& session_state() {
        thread_local std::unordered_map<SessionT*, SessionState> state;
        return state;
    }

    std::shared_ptr<store::StoreClient> store_client_;
    PlayerChannel player_channel_;
};

} // namespace netsrv::examples
