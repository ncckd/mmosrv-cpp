#pragma once
// hmac.hpp
//
// HMAC-SHA256 via l'API EVP_MAC d'OpenSSL 3.x (remplace l'ancienne
// fonction HMAC() depreciee depuis OpenSSL 3.0). Sert a authentifier
// chaque message du protocole INTERNE (Login/World <-> magasin partage
// heberge par Master, voir store/*.hpp) : un attaquant qui atteint le
// port interne sans connaitre le secret partage ne peut ni lire ni forger
// de requete valide -- HMAC apporte authenticite + integrite, PAS la
// confidentialite (voir README pour la note sur le chiffrement).
//
// Ne JAMAIS reimplementer HMAC/SHA256 a la main : c'est le genre de code
// ou une erreur subtile est invisible en test et catastrophique en prod.
// On s'appuie sur une bibliotheque auditee.

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <array>
#include <memory>
#include <span>
#include <stdexcept>

namespace netsrv::security {

inline constexpr std::size_t kHmacSize = 32; // SHA-256 => 32 octets
using HmacDigest = std::array<std::byte, kHmacSize>;

inline HmacDigest hmac_sha256(std::span<const std::byte> key, std::span<const std::byte> data) {
    std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)> mac(
        EVP_MAC_fetch(nullptr, "HMAC", nullptr), &EVP_MAC_free);
    if (!mac) throw std::runtime_error("HMAC: EVP_MAC_fetch a echoue");

    std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> ctx(
        EVP_MAC_CTX_new(mac.get()), &EVP_MAC_CTX_free);
    if (!ctx) throw std::runtime_error("HMAC: EVP_MAC_CTX_new a echoue");

    char digest_name[] = "SHA256";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, 0),
        OSSL_PARAM_construct_end(),
    };

    if (EVP_MAC_init(ctx.get(), reinterpret_cast<const unsigned char*>(key.data()),
                      key.size(), params) != 1)
        throw std::runtime_error("HMAC: EVP_MAC_init a echoue");

    if (!data.empty() &&
        EVP_MAC_update(ctx.get(), reinterpret_cast<const unsigned char*>(data.data()),
                        data.size()) != 1)
        throw std::runtime_error("HMAC: EVP_MAC_update a echoue");

    HmacDigest out{};
    std::size_t out_len = 0;
    if (EVP_MAC_final(ctx.get(), reinterpret_cast<unsigned char*>(out.data()),
                       &out_len, out.size()) != 1 || out_len != kHmacSize)
        throw std::runtime_error("HMAC: EVP_MAC_final a echoue");

    return out;
}

// Comparaison a temps CONSTANT : un simple `==`/memcmp s'arrete au
// premier octet different, ce qui fuite un timing exploitable pour
// deviner un MAC valide octet par octet. CRYPTO_memcmp (OpenSSL) est
// concu specifiquement pour eviter cette classe d'attaque.
inline bool constant_time_equal(std::span<const std::byte> a, std::span<const std::byte> b) noexcept {
    if (a.size() != b.size()) return false;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

} // namespace netsrv::security
