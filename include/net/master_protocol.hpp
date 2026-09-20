#pragma once
// master_protocol.hpp
// Message unique envoye par Master au client : le ticket (usage unique,
// voir store/shared_store.hpp) ET l'adresse du Login vers lequel se
// rediriger -- c'est ce qui manquait dans la version precedente (Master
// n'indiquait jamais OU se connecter).

#include "net/byte_io.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace netsrv::master_proto {

inline std::vector<std::byte> encode_redirect(std::string_view ticket, std::string_view login_host,
                                               std::uint16_t login_port) {
    ByteWriter w;
    w.u16(static_cast<std::uint16_t>(ticket.size())); w.str(ticket);
    w.u16(static_cast<std::uint16_t>(login_host.size())); w.str(login_host);
    w.u16(login_port);
    return w.take();
}

struct Redirect { std::string ticket; std::string login_host; std::uint16_t login_port; };

inline std::optional<Redirect> decode_redirect(std::span<const std::byte> msg) {
    ByteReader r(msg);
    auto tlen = r.u16(); if (!tlen) return std::nullopt;
    auto ticket = r.str(*tlen); if (!ticket) return std::nullopt;
    auto hlen = r.u16(); if (!hlen) return std::nullopt;
    auto host = r.str(*hlen); if (!host) return std::nullopt;
    auto port = r.u16(); if (!port) return std::nullopt;
    return Redirect{ std::move(*ticket), std::move(*host), *port };
}

// Reponse d'erreur (aucun Login disponible, etc.) : message court,
// generique, jamais de detail precis (cf. anti-enumeration).
inline std::vector<std::byte> encode_error() {
    ByteWriter w;
    w.u16(0xFFFF);
    return w.take();
}
inline bool is_error(std::span<const std::byte> msg) {
    ByteReader r(msg);
    auto v = r.u16();
    return v && *v == 0xFFFF;
}

} // namespace netsrv::master_proto
