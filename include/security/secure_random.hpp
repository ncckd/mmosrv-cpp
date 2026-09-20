#pragma once
// secure_random.hpp
//
// Generation de jetons aleatoires cryptographiquement surs (RAND_bytes,
// OpenSSL). Ne PAS utiliser std::mt19937/std::random_device seuls pour un
// jeton de securite : rien dans le standard ne garantit qu'ils soient
// imprevisibles (random_device "peut" degenerer vers un PRNG deterministe
// sur certaines implementations) -- RAND_bytes s'appuie sur le CSPRNG du
// systeme (getrandom()/CryptGenRandom...), c'est le bon outil pour ca.

#include <openssl/rand.h>

#include <array>
#include <cstddef>
#include <span>
#include <stdexcept>
#include <string>

namespace netsrv::security {

template <std::size_t N>
std::array<std::byte, N> random_bytes() {
    std::array<std::byte, N> buf{};
    if (RAND_bytes(reinterpret_cast<unsigned char*>(buf.data()), static_cast<int>(N)) != 1)
        throw std::runtime_error("RAND_bytes: entropie systeme indisponible");
    return buf;
}

inline std::string to_hex(std::span<const std::byte> bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (std::byte b : bytes) {
        const auto v = static_cast<unsigned char>(b);
        out.push_back(digits[v >> 4]);
        out.push_back(digits[v & 0x0F]);
    }
    return out;
}

// Jeton opaque 128 bits (16 octets), encode en 32 caracteres hexa : assez
// d'entropie pour etre impossible a deviner par force brute dans la
// fenetre de TTL courte utilisee pour les tickets Master / jetons Login.
inline std::string generate_token_hex() {
    return to_hex(random_bytes<16>());
}

} // namespace netsrv::security
