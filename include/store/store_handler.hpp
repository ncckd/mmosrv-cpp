#pragma once
// store_handler.hpp
//
// Handler cote serveur pour le magasin partage : verifie systematiquement
// le HMAC de chaque message avant d'y toucher, puis applique
// Put/Get/Take. A binder UNIQUEMENT sur une interface privee/loopback
// (voir main.cpp) : HMAC authentifie et integre les messages, mais ne les
// CHIFFRE pas -- ne pas exposer ce port sur une interface publique sans
// TLS en plus (cf. limitations dans le README).
//
// Pas de net/channel.hpp ici volontairement : 3 operations etroitement
// couplees a SharedStore se lisent mieux en switch direct. Channel<> est
// reserve aux cas avec beaucoup d'opcodes independants (voir
// handlers/player_channel.hpp).

#include <asio.hpp>

#include <memory>
#include <span>
#include <vector>

#include "protocol.hpp"
#include "session.hpp"
#include "store/shared_store.hpp"
#include "store/store_wire.hpp"

namespace netsrv::store {

class StoreHandler {
public:
    StoreHandler(std::shared_ptr<SharedStore> store, std::vector<std::byte> hmac_key)
        : store_(std::move(store)), hmac_key_(std::move(hmac_key)) {}

    asio::awaitable<void> on_connect(Session<TcpProtocol, StoreHandler>&) { co_return; }

    asio::awaitable<void> on_message(Session<TcpProtocol, StoreHandler>& session,
                                      std::span<const std::byte> payload) {
        // decode_and_verify() peut lever (echec crypto environnemental,
        // extremement rare) : Session::run() rattrape deja toute
        // exception issue d'un handler, donc pas besoin de dupliquer un
        // try/catch ici -- au pire cette connexion interne se ferme.
        auto decoded = decode_and_verify(hmac_key_, payload);
        if (!decoded) co_return; // signature invalide/message tronque : ignore, sans indice

        switch (decoded->op) {
            case Op::Put:
                store_->put(decoded->key, decoded->value, std::chrono::seconds(decoded->ttl_seconds));
                co_await session.send(encode_ok(hmac_key_));
                break;
            case Op::Get:
                if (auto v = store_->get(decoded->key)) co_await session.send(encode_value(hmac_key_, *v));
                else co_await session.send(encode_not_found(hmac_key_));
                break;
            case Op::Take:
                if (auto v = store_->take(decoded->key)) co_await session.send(encode_value(hmac_key_, *v));
                else co_await session.send(encode_not_found(hmac_key_));
                break;
            case Op::ListPrefix: {
                auto entries = store_->list_prefix(decoded->key);
                co_await session.send(encode_list(hmac_key_, entries));
                break;
            }
            default:
                break; // Ok/Value/NotFound/Err sont des reponses, pas des requetes valides ici
        }
    }

    void on_disconnect(Session<TcpProtocol, StoreHandler>&) {}

private:
    std::shared_ptr<SharedStore> store_;
    std::vector<std::byte> hmac_key_;
};

} // namespace netsrv::store
