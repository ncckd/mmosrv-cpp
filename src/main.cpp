// main.cpp
//
// Binaire UNIQUE pilote par --role : master | login | world. Chaque role
// ne demarre QUE ses propres services -- un crash de World n'emporte ni
// Login ni Master, car ce sont des PROCESS separes.
//
// Exemples (3 process, typiquement 3 machines/conteneurs) :
//   export NETSRV_INTERNAL_SECRET=$(openssl rand -hex 32)
//   ./netsrv_demo --role=master
//   ./netsrv_demo --role=login --store-host=10.0.0.5 --store-port=3725 \
//                 --advertise-host=10.0.0.6 --accounts-db=accounts.db
//   ./netsrv_demo --role=world --store-host=10.0.0.5 --store-port=3725 \
//                 --advertise-host=10.0.0.7 --world-name=Azshara
//
// Avant le premier login, creez un compte avec l'outil dedie :
//   ./netsrv_create_account accounts.db admin "un mot de passe solide"

#include <asio.hpp>

#include <chrono>
#include <cstdlib>
#include <csignal>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "accounts/sqlite_account_repository.hpp"
#include "example_handlers.hpp" // WorldUdpHandler
#include "handlers/login_handler.hpp"
#include "handlers/master_handler.hpp"
#include "handlers/world_handler.hpp"
#include "protocol.hpp"
#include "registry/world_registry.hpp"
#include "server.hpp"
#include "server_role.hpp"
#include "store/shared_store.hpp"
#include "store/store_client.hpp"
#include "store/store_handler.hpp"

using namespace netsrv;
using namespace netsrv::examples;

namespace {

struct Args {
    std::string role;
    std::string store_host = "127.0.0.1";
    unsigned short store_port = 3725;
    std::string bind_address = "0.0.0.0";
    std::string advertise_host = "127.0.0.1"; // adresse que les AUTRES process utilisent pour nous joindre
    std::string accounts_db = "accounts.db";
    std::string world_name = "World-1";
};

std::optional<Args> parse_args(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];
        auto value_after = [&](std::string_view prefix) -> std::optional<std::string_view> {
            if (arg.starts_with(prefix)) return arg.substr(prefix.size());
            return std::nullopt;
        };
        if (auto v = value_after("--role="))               a.role = std::string(*v);
        else if (auto v = value_after("--store-host="))     a.store_host = std::string(*v);
        else if (auto v = value_after("--store-port="))     a.store_port = static_cast<unsigned short>(std::stoi(std::string(*v)));
        else if (auto v = value_after("--bind="))           a.bind_address = std::string(*v);
        else if (auto v = value_after("--advertise-host=")) a.advertise_host = std::string(*v);
        else if (auto v = value_after("--accounts-db="))    a.accounts_db = std::string(*v);
        else if (auto v = value_after("--world-name="))     a.world_name = std::string(*v);
    }
    if (a.role != "master" && a.role != "login" && a.role != "world") return std::nullopt;
    return a;
}

std::vector<std::byte> load_hmac_secret() {
    const char* env = std::getenv("NETSRV_INTERNAL_SECRET");
    if (!env || std::string_view(env).size() != 64) {
        std::cerr << "NETSRV_INTERNAL_SECRET manquant ou invalide "
                     "(attendu : 64 caracteres hexa -- generer avec "
                     "`openssl rand -hex 32`)\n";
        std::exit(1);
    }
    std::vector<std::byte> key(32);
    for (std::size_t i = 0; i < 32; ++i)
        key[i] = static_cast<std::byte>(std::stoi(std::string(env + i * 2, 2), nullptr, 16));
    return key;
}

asio::awaitable<void> sweep_loop(std::shared_ptr<store::SharedStore> store) {
    asio::steady_timer timer(co_await asio::this_coro::executor);
    for (;;) {
        timer.expires_after(std::chrono::seconds(30));
        auto [ec] = co_await timer.async_wait(asio::as_tuple(asio::use_awaitable));
        if (ec) co_return;
        store->sweep_expired();
    }
}

void run_master(const Args& args, asio::io_context& orchestrator) {
    auto hmac_key = load_hmac_secret();
    auto store = std::make_shared<store::SharedStore>();

    auto client_handler   = std::make_shared<MasterHandler>(store);
    auto internal_handler = std::make_shared<store::StoreHandler>(store, hmac_key);

    // Client-facing : redirige vers un Login. Internal : sert le magasin
    // partage (tickets + registre) a Login/World. NOTE SECURITE :
    // internal_server est bindee sur 127.0.0.1 en dur -- en prod
    // multi-machines, changez pour une IP de reseau prive (VPC), jamais
    // une interface publique.
    Server<TcpProtocol, ServerRole::Master, MasterHandler> client_server(
        client_handler, 3724, args.bind_address);
    Server<TcpProtocol, ServerRole::Internal, store::StoreHandler> internal_server(
        internal_handler, args.store_port, "127.0.0.1");

    client_server.start();
    internal_server.start();
    asio::co_spawn(orchestrator, sweep_loop(store), asio::detached);

    asio::signal_set signals(orchestrator, SIGINT, SIGTERM);
    signals.async_wait([&](const asio::error_code&, int) {
        std::cout << "\n[Master] arret demande, drainage...\n";
        client_server.stop();
        internal_server.stop();
        orchestrator.stop();
        std::cout << "[Master] arrete proprement.\n";
    });
    orchestrator.run();
}

void run_login(const Args& args, asio::io_context& orchestrator) {
    auto hmac_key = load_hmac_secret();
    auto store_client = std::make_shared<store::StoreClient>(
        orchestrator.get_executor(), args.store_host, args.store_port, hmac_key);
    auto accounts = std::make_shared<accounts::SqliteAccountRepository>(args.accounts_db);

    constexpr unsigned short kLoginPort = 3726; // distinct de 3724 (Master) et du store-port (3725 par defaut)
    auto handler = std::make_shared<LoginHandler>(store_client, accounts, hmac_key);
    Server<TcpProtocol, ServerRole::Login, LoginHandler> server(handler, kLoginPort, args.bind_address);
    server.start();

    // S'annonce dans le registre pour que Master puisse nous rediriger
    // des clients (voir registry/world_registry.hpp -- TTL 15s, rafraichi
    // toutes les 5s ; si ce process meurt, l'entree expire d'elle-meme).
    registry::LoginInfo self{ args.advertise_host, kLoginPort };
    std::string registry_key = std::string(registry::kLoginPrefix) + args.advertise_host + ":" + std::to_string(kLoginPort);
    asio::co_spawn(orchestrator,
        registry::heartbeat_loop(store_client, registry_key,
                                  [self] { return registry::encode(self); }),
        asio::detached);

    asio::signal_set signals(orchestrator, SIGINT, SIGTERM);
    signals.async_wait([&](const asio::error_code&, int) {
        std::cout << "\n[Login] arret demande, drainage...\n";
        server.stop();
        orchestrator.stop(); // libere orchestrator.run() (abandonne le heartbeat, sans consequence)
        std::cout << "[Login] arrete proprement.\n";
    });
    orchestrator.run();
}

void run_world(const Args& args, asio::io_context& orchestrator) {
    auto hmac_key = load_hmac_secret();
    auto store_client = std::make_shared<store::StoreClient>(
        orchestrator.get_executor(), args.store_host, args.store_port, hmac_key);

    auto tcp_handler = std::make_shared<WorldHandler>(store_client);
    auto udp_handler = std::make_shared<WorldUdpHandler>();

    constexpr unsigned short kTcpPort = 8085, kUdpPort = 8086;
    Server<TcpProtocol, ServerRole::World, WorldHandler>    tcp_server(tcp_handler, kTcpPort, args.bind_address);
    Server<UdpProtocol,  ServerRole::World, WorldUdpHandler> udp_server(udp_handler, kUdpPort, args.bind_address);
    tcp_server.start();
    udp_server.start();

    // Heartbeat avec population EN TEMPS REEL (relue a chaque battement
    // via tcp_server.active_connections(), voir server.hpp) : c'est ce
    // que Login lira pour construire la liste des mondes envoyee au client.
    std::string registry_key = std::string(registry::kWorldPrefix) + args.advertise_host + ":" + std::to_string(kTcpPort);
    std::string name = args.world_name, host = args.advertise_host;
    asio::co_spawn(orchestrator,
        registry::heartbeat_loop(store_client, registry_key,
            [&tcp_server, name, host]() -> std::vector<std::byte> {
                registry::WorldInfo info{ host, kTcpPort, name,
                    static_cast<std::uint32_t>(tcp_server.active_connections()) };
                return registry::encode(info);
            }),
        asio::detached);

    asio::signal_set signals(orchestrator, SIGINT, SIGTERM);
    signals.async_wait([&](const asio::error_code&, int) {
        std::cout << "\n[World] arret demande, drainage...\n";
        tcp_server.stop();
        udp_server.stop();
        orchestrator.stop(); // libere orchestrator.run() (abandonne le heartbeat, sans consequence)
        std::cout << "[World] arrete proprement.\n";
    });
    orchestrator.run();
}

} // namespace

int main(int argc, char** argv) {
    auto args = parse_args(argc, argv);
    if (!args) {
        std::cerr << "Usage: " << argv[0] << " --role=master|login|world "
                     "[--store-host=H] [--store-port=P] [--bind=ADDR] "
                     "[--advertise-host=ADDR] [--accounts-db=PATH] [--world-name=NAME]\n";
        return 1;
    }

    asio::io_context orchestrator;

    if (args->role == "master")     run_master(*args, orchestrator);
    else if (args->role == "login") run_login(*args, orchestrator);
    else if (args->role == "world") run_world(*args, orchestrator);

    return 0;
}
