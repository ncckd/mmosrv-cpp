#pragma once
// framing.hpp
//
// Constantes et utilitaires de framing partages par Session (session.hpp)
// et par le protocole interne du magasin partage (store/*.hpp). Prefixe de
// longueur 4 octets (big-endian) devant chaque message applicatif.

#include <bit>
#include <cstddef>
#include <cstdint>

namespace netsrv {

inline constexpr std::size_t kFrameHeaderSize = 4;

namespace detail {
    constexpr std::uint32_t byteswap32(std::uint32_t v) noexcept {
        return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) |
               ((v & 0x00FF0000u) >> 8)  | ((v & 0xFF000000u) >> 24);
    }
}

// Portable sans htonl() ni std::byteswap (C++23) : std::endian est du C++20.
inline std::uint32_t to_network(std::uint32_t v) noexcept {
    if constexpr (std::endian::native == std::endian::little) return detail::byteswap32(v);
    else return v;
}
inline std::uint32_t from_network(std::uint32_t v) noexcept { return to_network(v); }

} // namespace netsrv
