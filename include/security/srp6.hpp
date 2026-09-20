#pragma once
// srp6.hpp
//
// SRP-6a (Secure Remote Password), RFC 2945 / RFC 5054, avec H = SHA-256
// (plutot que le SHA-1 historique de la plupart des implementations
// "MMO-style" -- SHA-1 n'est plus un choix recommande pour du nouveau
// code en 2026).
//
// GROUPE : nombre premier "sur" (N = 2q+1, q premier) sur 2048 bits.
// GENERE ET VERIFIE PREMIER DANS CE PROJET via BN_generate_prime_ex(...,
// safe=1) + BN_check_prime() independant, PUIS fige ici comme constante --
// jamais recopie d'une valeur externe de memoire, pour eliminer tout
// risque de transcription sur une constante de securite. Generateur g=2,
// verifie de ne pas etre d'ordre trivial (g^2 mod N != 1).
//
// PROPRIETE DE SECURITE CENTRALE DE SRP6a : le serveur ne stocke JAMAIS
// le mot de passe, seulement (salt, verifier). Le mot de passe n'est
// JAMAIS transmis sur le reseau, meme chiffre -- ni a la creation du
// compte (cf. tools/create_account.cpp) ni au moment du login.
//
// SIMPLIFICATION ASSUMEE par rapport a RFC 5054 stricte : la preuve
// mutuelle utilise M1 = H(A|B|K), M2 = H(A|M1|K) plutot que la variante
// "avec separation de domaine" (XOR de H(N)/H(g), H(username)...) de la
// RFC. Le coeur cryptographique difficile -- l'echange Diffie-Hellman
// "aveugle" via v=g^x, qui empeche quiconque d'apprendre le mot de passe
// en observant le reseau, meme le serveur d'authentification lui-meme
// avant la verification -- reste fidele a SRP6a. Adaptez ces 2 formules
// si vous devez interoperer avec un client tiers exigeant la RFC stricte.

#include "security/hmac.hpp"   // constant_time_equal
#include "security/sha256.hpp"
#include "security/secure_random.hpp"

#include <openssl/bn.h>

#include <array>
#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace netsrv::security::srp6 {

inline constexpr std::string_view kGroupNHex =
    "F511360967F552BDE33F1CBAA2A7FB1952F54B0B98C5C43B0C41F5CDE6BDE52F"
    "23190FB594E944D74CD79557D372AA1896F8E50E4369090FB5951BE6365AF475"
    "E9110B93B9BA6628AF0F5C9AB386154C4C2A4107FD522255D138E092DEA66252"
    "4A45C3E0F405622641C69444663EFD1989325FCBE9DCE9BD5EE35DAF1A88B818"
    "E820992BCA6617258137105E432EBA98F9E27235C0FF535BD4B6B89F7A030C54"
    "BCE4BCA12CEED3AEBADBB567C05D8DB3755AECB83DAF494C8CE8F596B7FC72D0"
    "2C44D0C7D1CE96C329A6CF080B15A543327362BDCCAECE26BFB35F7A5D0A80A6"
    "F6EEBF818694AB4A0D2B3188A884BD94AD5B38E0C7B510AC532449CA2850A5EF";
inline constexpr unsigned long kGroupG = 2;
inline constexpr int kNBytes = 256; // 2048 bits / 8

// --- RAII BIGNUM / BN_CTX ---------------------------------------------
using BnPtr  = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using CtxPtr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;

inline BnPtr make_bn() { return BnPtr(BN_new(), &BN_free); }
inline CtxPtr make_ctx() { return CtxPtr(BN_CTX_new(), &BN_CTX_free); }

inline BnPtr bn_from_hex(std::string_view hex) {
    BIGNUM* raw = nullptr;
    if (!BN_hex2bn(&raw, std::string(hex).c_str()) || !raw)
        throw std::runtime_error("SRP6: BN_hex2bn a echoue");
    return BnPtr(raw, &BN_free);
}
inline BnPtr bn_from_bytes(std::span<const std::byte> bytes) {
    BIGNUM* raw = BN_bin2bn(reinterpret_cast<const unsigned char*>(bytes.data()),
                             static_cast<int>(bytes.size()), nullptr);
    if (!raw) throw std::runtime_error("SRP6: BN_bin2bn a echoue");
    return BnPtr(raw, &BN_free);
}
// Encodage a taille FIXE (BN_bn2binpad) : les entrees de hachage (u, M1,
// M2, k) doivent toujours faire la meme longueur quel que soit le nombre
// de zeros de tete de la valeur, sous peine d'ambiguite de parsing.
inline std::vector<std::byte> bn_to_bytes(const BIGNUM* bn, int len = kNBytes) {
    std::vector<std::byte> out(len);
    if (BN_bn2binpad(bn, reinterpret_cast<unsigned char*>(out.data()), len) < 0)
        throw std::runtime_error("SRP6: BN_bn2binpad a echoue (valeur plus grande que len ?)");
    return out;
}

namespace detail {

inline std::vector<std::byte> concat(std::initializer_list<std::span<const std::byte>> parts) {
    std::vector<std::byte> out;
    std::size_t total = 0; for (auto p : parts) total += p.size();
    out.reserve(total);
    for (auto p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

// x = H(salt | H(username | ":" | password))   [RFC 5054]
inline BnPtr compute_x(std::span<const std::byte> salt, std::string_view username, std::string_view password) {
    std::string inner_src = std::string(username) + ":" + std::string(password);
    auto inner = sha256(std::as_bytes(std::span{inner_src}));
    auto outer = sha256(concat({salt, std::as_bytes(std::span{inner})}));
    return bn_from_bytes(outer);
}

// k = H(N | PAD(g))   [RFC 5054, multiplicateur SRP6a]
inline BnPtr compute_k(const BIGNUM* N, const BIGNUM* g) {
    auto N_bytes = bn_to_bytes(N);
    auto g_bytes = bn_to_bytes(g);
    auto h = sha256(concat({N_bytes, g_bytes}));
    return bn_from_bytes(h);
}

inline BnPtr compute_u(std::span<const std::byte> A_bytes, std::span<const std::byte> B_bytes) {
    auto h = sha256(concat({A_bytes, B_bytes}));
    return bn_from_bytes(h);
}

inline std::array<std::byte, 32> compute_M1(std::span<const std::byte> A_bytes,
                                             std::span<const std::byte> B_bytes,
                                             std::span<const std::byte> K) {
    return sha256(concat({A_bytes, B_bytes, K}));
}
inline std::array<std::byte, 32> compute_M2(std::span<const std::byte> A_bytes,
                                             std::span<const std::byte> M1,
                                             std::span<const std::byte> K) {
    return sha256(concat({A_bytes, M1, K}));
}

} // namespace detail

// --- Enregistrement (calcule UNE fois, a la creation du compte) --------
struct Registration {
    std::vector<std::byte> salt;
    std::vector<std::byte> verifier;
};

inline Registration compute_verifier_with_salt(std::string_view username, std::string_view password,
                                                std::vector<std::byte> salt) {
    auto N = bn_from_hex(kGroupNHex);
    auto g = make_bn(); BN_set_word(g.get(), kGroupG);
    auto ctx = make_ctx();
    auto x = detail::compute_x(salt, username, password);

    auto v = make_bn();
    BN_mod_exp(v.get(), g.get(), x.get(), N.get(), ctx.get());

    return { std::move(salt), bn_to_bytes(v.get()) };
}

inline Registration compute_verifier(std::string_view username, std::string_view password) {
    auto salt_arr = random_bytes<16>();
    std::vector<std::byte> salt(salt_arr.begin(), salt_arr.end());
    return compute_verifier_with_salt(username, password, std::move(salt));
}

// --- Cote SERVEUR --------------------------------------------------------
// Etat a conserver entre les 2 messages d'une session Login (voir
// handlers/login_handler.hpp) : mouvable, non copiable (contient des BIGNUM).
struct ServerChallenge {
    BnPtr b;                       // ephemere prive du serveur
    BnPtr v;                       // verifier, garde pour l'etape 2
    std::vector<std::byte> B_bytes; // a envoyer au client
};

inline ServerChallenge server_begin(std::span<const std::byte> verifier_bytes) {
    auto N = bn_from_hex(kGroupNHex);
    auto g = make_bn(); BN_set_word(g.get(), kGroupG);
    auto ctx = make_ctx();
    auto k = detail::compute_k(N.get(), g.get());

    auto v = bn_from_bytes(verifier_bytes);
    auto b = make_bn();
    BN_rand_range(b.get(), N.get());

    auto kv = make_bn(); BN_mod_mul(kv.get(), k.get(), v.get(), N.get(), ctx.get());
    auto gb = make_bn(); BN_mod_exp(gb.get(), g.get(), b.get(), N.get(), ctx.get());
    auto B  = make_bn(); BN_mod_add(B.get(), kv.get(), gb.get(), N.get(), ctx.get());

    ServerChallenge out{ std::move(b), std::move(v), bn_to_bytes(B.get()) };
    return out;
}

struct ServerResult {
    bool ok = false;
    std::array<std::byte, 32> K{};
    std::vector<std::byte> M2;
};

inline ServerResult server_verify(const ServerChallenge& challenge,
                                   std::span<const std::byte> A_bytes,
                                   std::span<const std::byte> client_M1) {
    auto N = bn_from_hex(kGroupNHex);
    auto ctx = make_ctx();
    auto A = bn_from_bytes(A_bytes);

    // Garde-fou SRP critique : un A congru a 0 mod N permettrait a un
    // attaquant de forcer S=0 et de casser completement la preuve.
    auto A_mod_N = make_bn(); BN_nnmod(A_mod_N.get(), A.get(), N.get(), ctx.get());
    if (BN_is_zero(A_mod_N.get())) return {};

    auto u = detail::compute_u(A_bytes, challenge.B_bytes);
    if (BN_is_zero(u.get())) return {};

    // S = (A * v^u)^b mod N
    auto vu   = make_bn(); BN_mod_exp(vu.get(), challenge.v.get(), u.get(), N.get(), ctx.get());
    auto Avu  = make_bn(); BN_mod_mul(Avu.get(), A.get(), vu.get(), N.get(), ctx.get());
    auto S    = make_bn(); BN_mod_exp(S.get(), Avu.get(), challenge.b.get(), N.get(), ctx.get());

    auto K = sha256(bn_to_bytes(S.get()));
    auto expected_M1 = detail::compute_M1(A_bytes, challenge.B_bytes, K);
    if (!constant_time_equal(expected_M1, client_M1)) return {};

    auto M2 = detail::compute_M2(A_bytes, expected_M1, K);
    return { true, K, std::vector<std::byte>(M2.begin(), M2.end()) };
}

// --- Cote CLIENT (pour tools/client_sim.cpp -- "le client n'existe pas",
//     on simule) --------------------------------------------------------
struct ClientProof {
    std::vector<std::byte> A_bytes;
    std::array<std::byte, 32> M1{};
    std::array<std::byte, 32> K{};
};

inline ClientProof client_respond(std::string_view username, std::string_view password,
                                   std::span<const std::byte> salt,
                                   std::span<const std::byte> B_bytes) {
    auto N = bn_from_hex(kGroupNHex);
    auto g = make_bn(); BN_set_word(g.get(), kGroupG);
    auto ctx = make_ctx();
    auto k = detail::compute_k(N.get(), g.get());

    auto B = bn_from_bytes(B_bytes);
    auto B_mod_N = make_bn(); BN_nnmod(B_mod_N.get(), B.get(), N.get(), ctx.get());
    if (BN_is_zero(B_mod_N.get())) throw std::runtime_error("SRP6: B=0 recu du serveur, rejete");

    auto a = make_bn(); BN_rand_range(a.get(), N.get());
    auto A = make_bn(); BN_mod_exp(A.get(), g.get(), a.get(), N.get(), ctx.get());
    auto A_bytes = bn_to_bytes(A.get());

    auto u = detail::compute_u(A_bytes, B_bytes);
    auto x = detail::compute_x(salt, username, password);

    // S = (B - k*g^x) ^ (a + u*x) mod N
    auto gx  = make_bn(); BN_mod_exp(gx.get(), g.get(), x.get(), N.get(), ctx.get());
    auto kgx = make_bn(); BN_mod_mul(kgx.get(), k.get(), gx.get(), N.get(), ctx.get());
    auto base = make_bn(); BN_mod_sub(base.get(), B.get(), kgx.get(), N.get(), ctx.get());

    auto ux  = make_bn(); BN_mul(ux.get(), u.get(), x.get(), ctx.get());
    auto exp = make_bn(); BN_add(exp.get(), a.get(), ux.get());

    auto S = make_bn(); BN_mod_exp(S.get(), base.get(), exp.get(), N.get(), ctx.get());
    auto K = sha256(bn_to_bytes(S.get()));
    auto M1 = detail::compute_M1(A_bytes, B_bytes, K);

    return { std::move(A_bytes), M1, K };
}

inline bool client_verify_server(const ClientProof& proof, std::span<const std::byte> server_M2) {
    auto expected = detail::compute_M2(proof.A_bytes, proof.M1, proof.K);
    return constant_time_equal(expected, server_M2);
}

} // namespace netsrv::security::srp6
