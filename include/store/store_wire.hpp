#pragma once
// store_wire.hpp
//
// Format binaire du protocole interne (Login/World <-> Master), et
// signature HMAC de chaque message. Parsing systematiquement borne
// (ByteReader renvoie std::nullopt des qu'il manque des octets) : meme
// sur un canal "interne", on ne fait jamais confiance a un buffer venu du
// reseau sans le valider.
//
// Limite assumee : les entiers sont serialises en ORDRE HOTE (pas de
// conversion reseau ici), car ce protocole ne circule qu'entre vos propres
// process sur des architectures homogenes (x86_64/ARM64, toutes deux
// little-endian en pratique). A corriger si vous deployez sur un parc
// heterogene en endianness.
//
// Enveloppe (apres le prefixe de longueur de net/framing.hpp) :
//   [u16 opcode]
//   [u16 key_len][key]
//   [u32 value_len][value]     -- vide si non applicable
//   [u32 ttl_seconds]          -- 0 si non applicable
//   [32 octets HMAC]           -- sur tout ce qui precede

#include "net/byte_io.hpp"
#include "security/hmac.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace netsrv::store {

enum class Op : std::uint16_t {
    Put = 1, Get = 2, Take = 3, ListPrefix = 4,                  // requetes
    Ok = 100, Value = 101, NotFound = 102, Err = 103, List = 104, // reponses
};

inline std::vector<std::byte> encode_put(std::span<const std::byte> hmac_key, std::string_view key,
                                          std::span<const std::byte> value, std::uint32_t ttl_seconds) {
    ByteWriter w;
    w.u16(static_cast<std::uint16_t>(Op::Put));
    w.u16(static_cast<std::uint16_t>(key.size())); w.str(key);
    w.u32(static_cast<std::uint32_t>(value.size())); w.bytes(value);
    w.u32(ttl_seconds);
    auto mac = security::hmac_sha256(hmac_key, w.view());
    w.bytes(mac);
    return w.take();
}

inline std::vector<std::byte> encode_get_or_take(Op op, std::span<const std::byte> hmac_key,
                                                  std::string_view key) {
    ByteWriter w;
    w.u16(static_cast<std::uint16_t>(op));
    w.u16(static_cast<std::uint16_t>(key.size())); w.str(key);
    w.u32(0); // value_len (absent)
    w.u32(0); // ttl (absent)
    auto mac = security::hmac_sha256(hmac_key, w.view());
    w.bytes(mac);
    return w.take();
}

inline std::vector<std::byte> encode_ok(std::span<const std::byte> hmac_key) {
    ByteWriter w;
    w.u16(static_cast<std::uint16_t>(Op::Ok));
    auto mac = security::hmac_sha256(hmac_key, w.view());
    w.bytes(mac);
    return w.take();
}

inline std::vector<std::byte> encode_not_found(std::span<const std::byte> hmac_key) {
    ByteWriter w;
    w.u16(static_cast<std::uint16_t>(Op::NotFound));
    auto mac = security::hmac_sha256(hmac_key, w.view());
    w.bytes(mac);
    return w.take();
}

inline std::vector<std::byte> encode_value(std::span<const std::byte> hmac_key,
                                            std::span<const std::byte> value) {
    ByteWriter w;
    w.u16(static_cast<std::uint16_t>(Op::Value));
    w.u32(static_cast<std::uint32_t>(value.size())); w.bytes(value);
    auto mac = security::hmac_sha256(hmac_key, w.view());
    w.bytes(mac);
    return w.take();
}

// ListPrefix : reutilise encode_get_or_take (meme forme : opcode + cle),
// la "cle" etant ici le prefixe recherche.
inline std::vector<std::byte> encode_list_prefix(std::span<const std::byte> hmac_key,
                                                  std::string_view prefix) {
    return encode_get_or_take(Op::ListPrefix, hmac_key, prefix);
}

using Entry = std::pair<std::string, std::vector<std::byte>>;

inline std::vector<std::byte> encode_list(std::span<const std::byte> hmac_key,
                                           const std::vector<Entry>& entries) {
    ByteWriter w;
    w.u16(static_cast<std::uint16_t>(Op::List));
    w.u32(static_cast<std::uint32_t>(entries.size()));
    for (const auto& [k, v] : entries) {
        w.u16(static_cast<std::uint16_t>(k.size())); w.str(k);
        w.u32(static_cast<std::uint32_t>(v.size())); w.bytes(v);
    }
    auto mac = security::hmac_sha256(hmac_key, w.view());
    w.bytes(mac);
    return w.take();
}

struct Decoded {
    Op op;
    std::string key;
    std::vector<std::byte> value;
    std::uint32_t ttl_seconds = 0;
    std::vector<Entry> entries; // reponse List uniquement
};

// Verifie le HMAC (temps constant) PUIS parse. Retourne nullopt si le
// message est tronque OU si la signature ne correspond pas -- dans les
// deux cas l'appelant doit fermer la connexion sans donner plus de
// details : ne pas distinguer "mal forme" de "mal signe" cote reponse
// evite de donner des indices a qui teste le canal sans le secret.
inline std::optional<Decoded> decode_and_verify(std::span<const std::byte> hmac_key,
                                                  std::span<const std::byte> msg) {
    if (msg.size() < security::kHmacSize + sizeof(std::uint16_t)) return std::nullopt;

    const auto body = msg.first(msg.size() - security::kHmacSize);
    const auto received_mac = msg.last(security::kHmacSize);
    const auto expected_mac = security::hmac_sha256(hmac_key, body);
    if (!security::constant_time_equal(received_mac, std::span<const std::byte>(expected_mac)))
        return std::nullopt;

    ByteReader r(body);
    auto opcode = r.u16();
    if (!opcode) return std::nullopt;
    const auto op = static_cast<Op>(*opcode);

    Decoded d; d.op = op;
    switch (op) {
        case Op::Put: {
            auto klen = r.u16(); if (!klen) return std::nullopt;
            auto key  = r.str(*klen); if (!key) return std::nullopt;
            auto vlen = r.u32(); if (!vlen) return std::nullopt;
            auto val  = r.bytes(*vlen); if (!val) return std::nullopt;
            auto ttl  = r.u32(); if (!ttl) return std::nullopt;
            d.key = std::move(*key); d.value = std::move(*val); d.ttl_seconds = *ttl;
            return d;
        }
        case Op::Get:
        case Op::Take:
        case Op::ListPrefix: {
            auto klen = r.u16(); if (!klen) return std::nullopt;
            auto key  = r.str(*klen); if (!key) return std::nullopt;
            d.key = std::move(*key);
            return d;
        }
        case Op::Value: {
            auto vlen = r.u32(); if (!vlen) return std::nullopt;
            auto val  = r.bytes(*vlen); if (!val) return std::nullopt;
            d.value = std::move(*val);
            return d;
        }
        case Op::List: {
            auto count = r.u32(); if (!count) return std::nullopt;
            if (*count > 100000) return std::nullopt; // garde-fou, pas de taille demesuree
            d.entries.reserve(*count);
            for (std::uint32_t i = 0; i < *count; ++i) {
                auto klen = r.u16(); if (!klen) return std::nullopt;
                auto key  = r.str(*klen); if (!key) return std::nullopt;
                auto vlen = r.u32(); if (!vlen) return std::nullopt;
                auto val  = r.bytes(*vlen); if (!val) return std::nullopt;
                d.entries.emplace_back(std::move(*key), std::move(*val));
            }
            return d;
        }
        case Op::Ok:
        case Op::NotFound:
        case Op::Err:
            return d;
    }
    return std::nullopt;
}

} // namespace netsrv::store
