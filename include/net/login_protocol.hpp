#pragma once
// login_protocol.hpp
//
// Echange multi-messages entre le client et Login, au-dessus du framing
// deja fourni par Session (chaque appel a decode() traite UN message deja
// desassemble par la couche longueur-prefixee) :
//
//   Client -> Login : ClientHello   { ticket, username }
//   Login  -> Client : ServerChallenge { salt, B }         (ou ServerError)
//   Client -> Login : ClientProof   { A, M1 }
//   Login  -> Client : ServerProof  { M2, session_token }  (ou ServerError)
//   Login  -> Client : WorldList    { [{name, host, port, population}, ...] }
//
// Pas de HMAC ici (contrairement a store_wire.hpp) : la securite de cet
// echange vient de SRP6a lui-meme (security/srp6.hpp), qui ne suppose
// aucun secret partage prealable avec le client -- c'est justement
// l'interet de SRP. Voir le README pour la note sur l'ajout de TLS en
// complement (confidentialite, que SRP6a n'apporte pas a lui seul).

#include "net/byte_io.hpp"

#include <array>
#include <algorithm>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace netsrv::login_proto {

enum class Op : std::uint16_t {
    ClientHello = 1, ClientProof = 2,
    ServerChallenge = 100, ServerProof = 101, ServerError = 102, WorldList = 103,
};

struct WorldEntry {
    std::string name;
    std::string host;
    std::uint16_t port = 0;
    std::uint32_t population = 0;
};

inline std::vector<std::byte> encode_client_hello(std::string_view ticket, std::string_view username) {
    ByteWriter w;
    w.u16(static_cast<std::uint16_t>(Op::ClientHello));
    w.u16(static_cast<std::uint16_t>(ticket.size())); w.str(ticket);
    w.u16(static_cast<std::uint16_t>(username.size())); w.str(username);
    return w.take();
}

inline std::vector<std::byte> encode_client_proof(std::span<const std::byte> A, std::span<const std::byte> M1) {
    ByteWriter w;
    w.u16(static_cast<std::uint16_t>(Op::ClientProof));
    w.u32(static_cast<std::uint32_t>(A.size())); w.bytes(A);
    w.bytes(M1); // toujours 32 octets (SHA-256) : pas besoin de longueur
    return w.take();
}

inline std::vector<std::byte> encode_server_challenge(std::span<const std::byte> salt, std::span<const std::byte> B) {
    ByteWriter w;
    w.u16(static_cast<std::uint16_t>(Op::ServerChallenge));
    w.u16(static_cast<std::uint16_t>(salt.size())); w.bytes(salt);
    w.u32(static_cast<std::uint32_t>(B.size())); w.bytes(B);
    return w.take();
}

inline std::vector<std::byte> encode_server_proof(std::span<const std::byte> M2, std::string_view session_token) {
    ByteWriter w;
    w.u16(static_cast<std::uint16_t>(Op::ServerProof));
    w.bytes(M2);
    w.u16(static_cast<std::uint16_t>(session_token.size())); w.str(session_token);
    return w.take();
}

inline std::vector<std::byte> encode_error() {
    ByteWriter w;
    w.u16(static_cast<std::uint16_t>(Op::ServerError));
    return w.take();
}

inline std::vector<std::byte> encode_world_list(const std::vector<WorldEntry>& worlds) {
    ByteWriter w;
    w.u16(static_cast<std::uint16_t>(Op::WorldList));
    w.u32(static_cast<std::uint32_t>(worlds.size()));
    for (const auto& wd : worlds) {
        w.u16(static_cast<std::uint16_t>(wd.name.size())); w.str(wd.name);
        w.u16(static_cast<std::uint16_t>(wd.host.size())); w.str(wd.host);
        w.u16(wd.port);
        w.u32(wd.population);
    }
    return w.take();
}

struct Decoded {
    Op op{};
    std::string ticket, username;
    std::vector<std::byte> A;
    std::array<std::byte, 32> M1{};
    std::vector<std::byte> salt, B;
    std::array<std::byte, 32> M2{};
    std::string session_token;
    std::vector<WorldEntry> worlds;
};

inline std::optional<Decoded> decode(std::span<const std::byte> msg) {
    ByteReader r(msg);
    auto opcode = r.u16(); if (!opcode) return std::nullopt;
    Decoded d; d.op = static_cast<Op>(*opcode);

    switch (d.op) {
        case Op::ClientHello: {
            auto tlen = r.u16(); if (!tlen) return std::nullopt;
            auto t = r.str(*tlen); if (!t) return std::nullopt;
            auto ulen = r.u16(); if (!ulen) return std::nullopt;
            auto u = r.str(*ulen); if (!u) return std::nullopt;
            d.ticket = std::move(*t); d.username = std::move(*u);
            return d;
        }
        case Op::ClientProof: {
            auto alen = r.u32(); if (!alen) return std::nullopt;
            auto a = r.bytes(*alen); if (!a) return std::nullopt;
            auto m1 = r.bytes(32); if (!m1 || m1->size() != 32) return std::nullopt;
            d.A = std::move(*a);
            std::copy(m1->begin(), m1->end(), d.M1.begin());
            return d;
        }
        case Op::ServerChallenge: {
            auto slen = r.u16(); if (!slen) return std::nullopt;
            auto s = r.bytes(*slen); if (!s) return std::nullopt;
            auto blen = r.u32(); if (!blen) return std::nullopt;
            auto b = r.bytes(*blen); if (!b) return std::nullopt;
            d.salt = std::move(*s); d.B = std::move(*b);
            return d;
        }
        case Op::ServerProof: {
            auto m2 = r.bytes(32); if (!m2 || m2->size() != 32) return std::nullopt;
            std::copy(m2->begin(), m2->end(), d.M2.begin());
            auto tlen = r.u16(); if (!tlen) return std::nullopt;
            auto t = r.str(*tlen); if (!t) return std::nullopt;
            d.session_token = std::move(*t);
            return d;
        }
        case Op::ServerError:
            return d;
        case Op::WorldList: {
            auto count = r.u32(); if (!count) return std::nullopt;
            if (*count > 10000) return std::nullopt; // garde-fou
            d.worlds.reserve(*count);
            for (std::uint32_t i = 0; i < *count; ++i) {
                auto nlen = r.u16(); if (!nlen) return std::nullopt;
                auto name = r.str(*nlen); if (!name) return std::nullopt;
                auto hlen = r.u16(); if (!hlen) return std::nullopt;
                auto host = r.str(*hlen); if (!host) return std::nullopt;
                auto port = r.u16(); if (!port) return std::nullopt;
                auto pop = r.u32(); if (!pop) return std::nullopt;
                d.worlds.push_back({ std::move(*name), std::move(*host), *port, *pop });
            }
            return d;
        }
    }
    return std::nullopt;
}

} // namespace netsrv::login_proto
