#pragma once
// sha256.hpp
// Hash SHA-256 "simple" (pas HMAC) via l'API EVP_Digest d'OpenSSL -- brique
// de base de SRP6a (security/srp6.hpp). Voir security/hmac.hpp pour la
// version authentifiee (HMAC) utilisee par le protocole interne.

#include <openssl/evp.h>

#include <array>
#include <cstddef>
#include <span>
#include <stdexcept>

namespace netsrv::security {

inline std::array<std::byte, 32> sha256(std::span<const std::byte> data) {
    std::array<std::byte, 32> out{};
    unsigned int out_len = 0;
    if (EVP_Digest(data.data(), data.size(), reinterpret_cast<unsigned char*>(out.data()),
                    &out_len, EVP_sha256(), nullptr) != 1 || out_len != 32)
        throw std::runtime_error("SHA-256: EVP_Digest a echoue");
    return out;
}

} // namespace netsrv::security
