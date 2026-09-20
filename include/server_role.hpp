#pragma once
// server_role.hpp
//
// Deuxieme parametre template : le ROLE du serveur (Master / Login / World),
// avec une configuration (nb de threads, taille de buffer, timeout, capacite
// max) fixee a la compilation via specialisation de template. Ce sont des
// constantes qui ne changent jamais au runtime : autant les rendre
// `constexpr` -> zero cout, et le compilateur peut les propager/optimiser.

#include <chrono>
#include <cstddef>
#include <string_view>

namespace netsrv {

// Internal : canal prive Login/World <-> Master (magasin partage de
// tickets/jetons de session). Jamais expose au client, jamais bindé sur
// une interface publique (voir main.cpp et README).
enum class ServerRole { Master, Login, World, Internal };

constexpr std::string_view to_string(ServerRole role) noexcept {
    switch (role) {
        case ServerRole::Master:   return "Master";
        case ServerRole::Login:    return "Login";
        case ServerRole::World:    return "World";
        case ServerRole::Internal: return "Internal";
    }
    return "Unknown";
}

// Configuration par role. Ajustez selon votre charge reelle mesuree
// (ces valeurs sont des points de depart raisonnables, pas des lois).
template <ServerRole Role>
struct ServerConfig;

template <>
struct ServerConfig<ServerRole::Master> {
    // Peu de connexions (supervision / inter-process), faible charge.
    static constexpr std::size_t max_connections  = 64;
    static constexpr std::size_t read_buffer_bytes = 4096;
    static constexpr std::size_t io_threads        = 1;   // 0 = hardware_concurrency()
    static constexpr std::chrono::seconds idle_timeout{120};
};

template <>
struct ServerConfig<ServerRole::Login> {
    // Beaucoup de connexions courtes (authentification), pic de churn.
    static constexpr std::size_t max_connections  = 8192;
    static constexpr std::size_t read_buffer_bytes = 2048;
    static constexpr std::size_t io_threads        = 0;   // auto
    static constexpr std::chrono::seconds idle_timeout{30};
};

template <>
struct ServerConfig<ServerRole::World> {
    // Beaucoup de connexions longues, debit soutenu (gameplay).
    static constexpr std::size_t max_connections  = 20000;
    static constexpr std::size_t read_buffer_bytes = 8192;
    static constexpr std::size_t io_threads        = 0;   // auto
    static constexpr std::chrono::seconds idle_timeout{300};
};

template <>
struct ServerConfig<ServerRole::Internal> {
    // Canal prive Login/World <-> Master (magasin partage). Peu de pairs
    // (une poignee de process), connexions tres courtes (une par requete,
    // voir store/store_client.hpp) : capacite modeste suffit largement.
    static constexpr std::size_t max_connections  = 256;
    static constexpr std::size_t read_buffer_bytes = 4096;
    static constexpr std::size_t io_threads        = 1;
    static constexpr std::chrono::seconds idle_timeout{10};
};

} // namespace netsrv
