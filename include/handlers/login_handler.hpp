#pragma once
// login_handler.hpp
//
// Etat machine a 2 etapes, par session, stocke dans une map THREAD_LOCAL
// (meme justification que world_handler.hpp : une session ne s'execute
// jamais que sur un seul thread, donc zero contention possible) :
//
//   1) ClientHello{ticket, username}
//        -> "take" le ticket aupres du magasin (reseau, StoreClient)
//        -> cherche le compte en base (SQLite, thread_local -> pas de
//           contention non plus)
//        -> genere un challenge SRP6 REEL (compte existant) ou FACTICE
//           mais indistinguable (compte inexistant : salt derive de facon
//           deterministe du username, verifier aleatoire) -- resistance a
//           l'enumeration de comptes : un attaquant ne peut pas savoir si
//           un username existe juste en regardant la reponse.
//        <- ServerChallenge{salt, B}
//
//   2) ClientProof{A, M1}
//        -> server_verify() (meme code, compte reel OU factice -- un
//           compte factice echoue TOUJOURS ici, indistinguablement d'un
//           mauvais mot de passe sur un compte reel)
//        <- ServerProof{M2, session_token} + WorldList
//           ou ServerError si M1 invalide

#include <asio.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>

#include "accounts/account_repository.hpp"
#include "net/login_protocol.hpp"
#include "protocol.hpp"
#include "registry/world_registry.hpp"
#include "security/secure_random.hpp"
#include "security/srp6.hpp"
#include "session.hpp"
#include "store/store_client.hpp"

namespace netsrv::examples {

class LoginHandler {
public:
    using SessionT = Session<TcpProtocol, LoginHandler>;

    LoginHandler(std::shared_ptr<store::StoreClient> store_client,
                 std::shared_ptr<accounts::AccountRepository> accounts,
                 std::vector<std::byte> enum_resistance_key,
                 std::chrono::seconds session_ttl = std::chrono::seconds(60))
        : store_client_(std::move(store_client))
        , accounts_(std::move(accounts))
        , enum_key_(std::move(enum_resistance_key))
        , session_ttl_(session_ttl) {}

    asio::awaitable<void> on_connect(SessionT&) { co_return; }

    asio::awaitable<void> on_message(SessionT& session, std::span<const std::byte> payload) {
        auto decoded = login_proto::decode(payload);
        if (!decoded) { session.close(); co_return; }

        auto& st = session_state()[&session];

        if (st.stage == Stage::AwaitingHello && decoded->op == login_proto::Op::ClientHello) {
            co_await handle_hello(session, st, decoded->ticket, decoded->username);
        } else if (st.stage == Stage::AwaitingProof && decoded->op == login_proto::Op::ClientProof) {
            co_await handle_proof(session, st, decoded->A, decoded->M1);
        } else {
            session.close(); // message hors sequence : on ne tente pas de "rattraper"
        }
    }

    void on_disconnect(SessionT& session) {
        session_state().erase(&session);
    }

private:
    enum class Stage { AwaitingHello, AwaitingProof, Done };
    struct SessionState {
        Stage stage = Stage::AwaitingHello;
        std::string username;
        std::optional<security::srp6::ServerChallenge> challenge;
    };

    static std::unordered_map<SessionT*, SessionState>& session_state() {
        thread_local std::unordered_map<SessionT*, SessionState> state;
        return state;
    }

    asio::awaitable<void> handle_hello(SessionT& session, SessionState& st,
                                        const std::string& ticket, const std::string& username) {
        auto found_ticket = co_await store_client_->take(ticket);

        if (!found_ticket) {
            session.close();
            co_return;
        }

        std::optional<accounts::AccountRecord> account;
        bool account_lookup_failed = false;

        try {
            account = accounts_->find(username);
        }
        catch (const std::exception&) {
            account_lookup_failed = true;
        }

        if (account_lookup_failed) {
            co_await session.send(login_proto::encode_error());
            session.close();
            co_return;
        }

        security::srp6::Registration reg;
        if (account) {
            reg = { account->salt, account->verifier };
        } else {
            // Compte inexistant : challenge FACTICE mais indistinguable
            // (voir commentaire en tete de fichier).
            reg = security::srp6::compute_verifier_with_salt(
                username, security::generate_token_hex(), fake_salt_for(username));
        }

        auto challenge = security::srp6::server_begin(reg.verifier);
        auto response = login_proto::encode_server_challenge(reg.salt, challenge.B_bytes);

        st.username = username;
        st.challenge = std::move(challenge);
        st.stage = Stage::AwaitingProof;

        co_await session.send(response);
    }

    asio::awaitable<void> handle_proof(SessionT& session, SessionState& st,
                                        std::span<const std::byte> A, std::span<const std::byte> M1) {
        auto result = security::srp6::server_verify(*st.challenge, A, M1);
        if (!result.ok) {
            // Meme reponse, que le compte soit factice OU que le mot de
            // passe soit simplement faux sur un compte reel.
            co_await session.send(login_proto::encode_error());
            session.close();
            co_return;
        }

        const std::string session_token = security::generate_token_hex();
        std::vector<std::byte> username_bytes(
            reinterpret_cast<const std::byte*>(st.username.data()),
            reinterpret_cast<const std::byte*>(st.username.data()) + st.username.size());
        co_await store_client_->put(session_token, username_bytes, session_ttl_);

        co_await session.send(login_proto::encode_server_proof(result.M2, session_token));

        auto worlds = co_await registry::list_worlds(store_client_);
        std::vector<login_proto::WorldEntry> entries;
        entries.reserve(worlds.size());
        for (auto& w : worlds) entries.push_back({ w.name, w.host, w.port, w.population });
        co_await session.send(login_proto::encode_world_list(entries));

        st.stage = Stage::Done;
    }

    // Salt deterministe par username (mais imprevisible sans enum_key_) :
    // meme salt a chaque tentative pour un username donne, qu'il existe
    // ou non -- sans ca, un attaquant verrait un salt DIFFERENT a chaque
    // essai sur un compte inexistant et en deduirait sa non-existence.
    std::vector<std::byte> fake_salt_for(std::string_view username) const {
        std::string label = "srp6-fake-salt:" + std::string(username);
        auto h = security::hmac_sha256(enum_key_, std::as_bytes(std::span{label}));
        return std::vector<std::byte>(h.begin(), h.begin() + 16);
    }

    std::shared_ptr<store::StoreClient> store_client_;
    std::shared_ptr<accounts::AccountRepository> accounts_;
    std::vector<std::byte> enum_key_;
    std::chrono::seconds session_ttl_;
};

} // namespace netsrv::examples
