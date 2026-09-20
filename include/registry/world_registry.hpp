#pragma once
// world_registry.hpp
//
// Reutilise le magasin partage (store/*) comme registre de services,
// auto-nettoyant : Login et World ecrivent periodiquement leur propre
// entree avec un TTL court (heartbeat) ; si un process meurt, son entree
// expire toute seule et disparait du registre -- aucun protocole de
// heartbeat/detection de panne separe a maintenir.
//
//   registry:login:<id>  -> LoginInfo { host, port }
//   registry:world:<id>  -> WorldInfo { host, port, name, population }
//
// Master lit le registre EN MEMOIRE (SharedStore direct, meme process).
// Login lit/ecrit le registre PAR RESEAU (StoreClient, process separe).

#include <asio.hpp>

#include "net/byte_io.hpp"
#include "store/shared_store.hpp"
#include "store/store_client.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace netsrv::registry {

inline constexpr std::string_view kLoginPrefix = "registry:login:";
inline constexpr std::string_view kWorldPrefix = "registry:world:";

struct LoginInfo { std::string host; std::uint16_t port; };
struct WorldInfo { std::string host; std::uint16_t port; std::string name; std::uint32_t population; };

inline std::vector<std::byte> encode(const LoginInfo& i) {
    ByteWriter w;
    w.u16(static_cast<std::uint16_t>(i.host.size())); w.str(i.host);
    w.u16(i.port);
    return w.take();
}
inline std::optional<LoginInfo> decode_login(std::span<const std::byte> data) {
    ByteReader r(data);
    auto hlen = r.u16(); if (!hlen) return std::nullopt;
    auto host = r.str(*hlen); if (!host) return std::nullopt;
    auto port = r.u16(); if (!port) return std::nullopt;
    return LoginInfo{ std::move(*host), *port };
}

inline std::vector<std::byte> encode(const WorldInfo& i) {
    ByteWriter w;
    w.u16(static_cast<std::uint16_t>(i.host.size())); w.str(i.host);
    w.u16(i.port);
    w.u16(static_cast<std::uint16_t>(i.name.size())); w.str(i.name);
    w.u32(i.population);
    return w.take();
}
inline std::optional<WorldInfo> decode_world(std::span<const std::byte> data) {
    ByteReader r(data);
    auto hlen = r.u16(); if (!hlen) return std::nullopt;
    auto host = r.str(*hlen); if (!host) return std::nullopt;
    auto port = r.u16(); if (!port) return std::nullopt;
    auto nlen = r.u16(); if (!nlen) return std::nullopt;
    auto name = r.str(*nlen); if (!name) return std::nullopt;
    auto pop = r.u32(); if (!pop) return std::nullopt;
    return WorldInfo{ std::move(*host), *port, std::move(*name), *pop };
}

// --- Cote registrant (Login/World, via le reseau) -----------------------
// A co_spawn-er en "detached" au demarrage (voir main.cpp). S'arrete
// silencieusement quand l'executeur est ferme (arret du process) : sans
// consequence, l'entree expire d'elle-meme au pire kTtl plus tard.
// `value_provider` est appelee a CHAQUE battement (pas une seule fois) :
// utile pour World, qui veut rapporter sa population EN TEMPS REEL a
// chaque heartbeat plutot qu'une valeur figee au demarrage.
inline asio::awaitable<void> heartbeat_loop(std::shared_ptr<store::StoreClient> client,
                                             std::string key,
                                             std::function<std::vector<std::byte>()> value_provider,
                                             std::chrono::seconds interval = std::chrono::seconds(5),
                                             std::chrono::seconds ttl = std::chrono::seconds(15)) {
    asio::steady_timer timer(co_await asio::this_coro::executor);
    for (;;) {
        co_await client->put(key, value_provider(), ttl);
        timer.expires_after(interval);
        auto [ec] = co_await timer.async_wait(asio::as_tuple(asio::use_awaitable));
        if (ec) co_return;
    }
}

// --- Cote lecteur reseau (Login lit la liste des World) -----------------
inline asio::awaitable<std::vector<WorldInfo>> list_worlds(std::shared_ptr<store::StoreClient> client) {
    auto entries = co_await client->list_prefix(kWorldPrefix);
    std::vector<WorldInfo> out;
    out.reserve(entries.size());
    for (auto& [k, v] : entries)
        if (auto info = decode_world(v)) out.push_back(std::move(*info));
    co_return out;
}

// --- Cote lecteur direct (Master lit la liste des Login, meme process) --
// Choix simple : le premier de la liste. TODO pour plusieurs Login :
// round-robin ou "le moins charge" (ajoutez un compteur de connexions
// actives dans LoginInfo et comparez ici).
inline std::optional<LoginInfo> pick_login(store::SharedStore& store) {
    auto entries = store.list_prefix(std::string(kLoginPrefix));
    if (entries.empty()) return std::nullopt;
    return decode_login(entries.front().second);
}

} // namespace netsrv::registry
