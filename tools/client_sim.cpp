// client_sim.cpp
//
// "Le client n'existe pas" : ce programme simule le comportement attendu
// d'un vrai client de jeu pour exercer toute la chaine Master -> Login,
// SRP6a compris, jusqu'a la reception de la liste des mondes.
//
// Usage:
//   ./netsrv_client_sim <master_host> <master_port> <username> <password>
//   ./netsrv_client_sim 127.0.0.1 3724 admin "correct horse battery staple"
//
// NOTE : contrairement au code serveur (session.hpp, handlers/*), ce
// fichier utilise volontairement la forme "throwing" par defaut d'Asio
// (asio::use_awaitable sans as_tuple) plutot que error_code partout : un
// outil client en ligne de commande peut se permettre de s'arreter avec
// un message clair sur la premiere erreur reseau, ce qu'un serveur qui
// sert des milliers de clients ne peut pas se permettre.

#include <asio.hpp>

#include "net/framing.hpp"
#include "net/login_protocol.hpp"
#include "net/master_protocol.hpp"
#include "security/srp6.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <vector>

using namespace netsrv;

namespace {

asio::awaitable<std::optional<std::vector<std::byte>>> read_frame(asio::ip::tcp::socket& socket) {
    std::array<std::byte, kFrameHeaderSize> header{};
    auto [ec1, n1] = co_await asio::async_read(socket, asio::buffer(header), asio::as_tuple(asio::use_awaitable));
    if (ec1 || n1 != kFrameHeaderSize) co_return std::nullopt;

    std::uint32_t len_be{};
    std::memcpy(&len_be, header.data(), kFrameHeaderSize);
    const std::uint32_t len = from_network(len_be);
    if (len == 0 || len > (1u << 20)) co_return std::nullopt;

    std::vector<std::byte> body(len);
    auto [ec2, n2] = co_await asio::async_read(socket, asio::buffer(body), asio::as_tuple(asio::use_awaitable));
    if (ec2 || n2 != len) co_return std::nullopt;
    co_return body;
}

asio::awaitable<bool> write_frame(asio::ip::tcp::socket& socket, std::span<const std::byte> payload) {
    std::array<std::byte, kFrameHeaderSize> header{};
    const std::uint32_t be_len = to_network(static_cast<std::uint32_t>(payload.size()));
    std::memcpy(header.data(), &be_len, kFrameHeaderSize);
    std::array<asio::const_buffer, 2> bufs{
        asio::buffer(header.data(), header.size()), asio::buffer(payload.data(), payload.size())
    };
    auto [ec, n] = co_await asio::async_write(socket, bufs, asio::as_tuple(asio::use_awaitable));
    co_return !ec;
}

asio::awaitable<void> run(std::string master_host, unsigned short master_port,
                           std::string username, std::string password) {
    auto exec = co_await asio::this_coro::executor;
    asio::ip::tcp::resolver resolver(exec);

    // --- 1. Master : obtenir un ticket + l'adresse de Login -------------
    auto master_eps = co_await resolver.async_resolve(master_host, std::to_string(master_port), asio::use_awaitable);
    asio::ip::tcp::socket master_socket(exec);
    co_await asio::async_connect(master_socket, master_eps, asio::use_awaitable);
    std::cout << "[client] connecte a Master " << master_host << ":" << master_port << "\n";

    std::string_view hello = "hello";
    co_await write_frame(master_socket, std::as_bytes(std::span{hello}));

    auto master_resp = co_await read_frame(master_socket);
    if (!master_resp) { std::cerr << "[client] pas de reponse de Master\n"; co_return; }
    if (master_proto::is_error(*master_resp)) {
        std::cerr << "[client] Master : aucun serveur Login disponible actuellement\n"; co_return;
    }
    auto redirect = master_proto::decode_redirect(*master_resp);
    if (!redirect) { std::cerr << "[client] reponse Master illisible\n"; co_return; }

    std::cout << "[client] Master -> ticket=" << redirect->ticket.substr(0, 8) << "...  redirection vers Login "
              << redirect->login_host << ":" << redirect->login_port << "\n";
    { asio::error_code ec; master_socket.close(ec); }

    // --- 2. Login : ClientHello (ticket + username) ----------------------
    auto login_eps = co_await resolver.async_resolve(redirect->login_host, std::to_string(redirect->login_port),
                                                       asio::use_awaitable);
    asio::ip::tcp::socket login_socket(exec);
    co_await asio::async_connect(login_socket, login_eps, asio::use_awaitable);
    std::cout << "[client] connecte a Login " << redirect->login_host << ":" << redirect->login_port << "\n";

    co_await write_frame(login_socket, login_proto::encode_client_hello(redirect->ticket, username));

    auto challenge_msg = co_await read_frame(login_socket);
    if (!challenge_msg) { std::cerr << "[client] pas de reponse Login (hello)\n"; co_return; }
    auto challenge = login_proto::decode(*challenge_msg);
    if (!challenge || challenge->op != login_proto::Op::ServerChallenge) {
        std::cerr << "[client] Login a refuse (ticket invalide/expire)\n"; co_return;
    }
    std::cout << "[client] challenge SRP6 recu (salt=" << challenge->salt.size()
              << "o, B=" << challenge->B.size() << "o)\n";

    // --- 3. Calcul SRP6a cote client (le mot de passe ne quitte JAMAIS
    //        ce process, meme chiffre) -----------------------------------
    auto proof = security::srp6::client_respond(username, password, challenge->salt, challenge->B);
    co_await write_frame(login_socket, login_proto::encode_client_proof(proof.A_bytes, proof.M1));

    auto proof_msg = co_await read_frame(login_socket);
    if (!proof_msg) { std::cerr << "[client] pas de reponse Login (proof)\n"; co_return; }
    auto server_proof = login_proto::decode(*proof_msg);
    if (!server_proof || server_proof->op != login_proto::Op::ServerProof) {
        std::cerr << "[client] authentification refusee (mauvais mot de passe ou compte inexistant)\n"; co_return;
    }

    if (!security::srp6::client_verify_server(proof, server_proof->M2)) {
        std::cerr << "[client] ALERTE : preuve du serveur (M2) invalide -- usurpation possible, on arrete.\n";
        co_return;
    }
    std::cout << "[client] authentifie -- preuve mutuelle du serveur verifiee (M2 OK)\n"
              << "[client] jeton de session : " << server_proof->session_token.substr(0, 8) << "...\n";

    // --- 4. Liste des mondes disponibles ---------------------------------
    auto worlds_msg = co_await read_frame(login_socket);
    if (!worlds_msg) { std::cerr << "[client] pas de liste de mondes recue\n"; co_return; }
    auto worlds = login_proto::decode(*worlds_msg);
    if (!worlds || worlds->op != login_proto::Op::WorldList) { std::cerr << "[client] reponse mondes illisible\n"; co_return; }

    std::cout << "\n=== Mondes disponibles (" << worlds->worlds.size() << ") ===\n";
    for (const auto& w : worlds->worlds)
        std::cout << "  - " << w.name << "  (" << w.host << ":" << w.port << ")  population=" << w.population << "\n";
    std::cout << "\n(le client choisirait maintenant un monde et s'y connecterait avec le jeton de session)\n";
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] << " <master_host> <master_port> <username> <password>\n";
        return 1;
    }
    try {
        asio::io_context io;
        asio::co_spawn(io,
            run(argv[1], static_cast<unsigned short>(std::stoi(argv[2])), argv[3], argv[4]),
            [](std::exception_ptr e) { if (e) std::rethrow_exception(e); });
        io.run();
    } catch (const std::exception& e) {
        std::cerr << "Erreur fatale: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
