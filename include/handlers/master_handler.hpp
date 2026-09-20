#pragma once
// master_handler.hpp
//
// Master joue 2 roles dans le meme process (voir main.cpp) :
//   1. Cote CLIENT (ce handler) : choisit un Login disponible dans le
//      REGISTRE (registry/world_registry.hpp, alimente par le heartbeat
//      de chaque instance Login) et renvoie {ticket, host, port} au
//      client -- c'est ce qui manquait avant : Master n'indiquait jamais
//      OU se connecter, seulement un ticket sans destination.
//   2. Cote INTERNE (store::StoreHandler) : heberge le magasin partage
//      (tickets ET registre de services) et l'expose a Login/World.
//
// Ce handler cote client accede au magasin DIRECTEMENT (meme processus,
// meme memoire) : pas besoin de reseau pour lui-meme.

#include <asio.hpp>

#include <chrono>
#include <memory>
#include <span>
#include <string>

#include "net/master_protocol.hpp"
#include "protocol.hpp"
#include "registry/world_registry.hpp"
#include "security/secure_random.hpp"
#include "session.hpp"
#include "store/shared_store.hpp"

namespace netsrv::examples {

class MasterHandler {
public:
    explicit MasterHandler(std::shared_ptr<store::SharedStore> store,
                            std::chrono::seconds ticket_ttl = std::chrono::seconds(30))
        : store_(std::move(store)), ticket_ttl_(ticket_ttl) {}

    asio::awaitable<void> on_connect(Session<TcpProtocol, MasterHandler>&) { co_return; }

    // N'importe quel message recu declenche la redirection. Dans un vrai
    // deploiement, ajoutez ICI vos verifications (rate limiting par IP,
    // liste noire, geo-routage, mode maintenance...) avant d'emettre quoi
    // que ce soit -- c'est precisement le travail qui justifie ce hop
    // plutot qu'un simple enregistrement DNS.
    asio::awaitable<void> on_message(Session<TcpProtocol, MasterHandler>& session,
                                      std::span<const std::byte>) {
        auto login = registry::pick_login(*store_);
        if (!login) {
            // Aucun Login disponible (tous en panne / pas encore demarres) :
            // erreur generique, jamais de detail (anti-enumeration).
            co_await session.send(master_proto::encode_error());
            co_return;
        }

        const std::string ticket = security::generate_token_hex();
        store_->put(ticket, {}, ticket_ttl_); // valeur vide : la possession du jeton suffit

        co_await session.send(master_proto::encode_redirect(ticket, login->host, login->port));
    }

    void on_disconnect(Session<TcpProtocol, MasterHandler>&) {}

private:
    std::shared_ptr<store::SharedStore> store_;
    std::chrono::seconds ticket_ttl_;
};

} // namespace netsrv::examples
