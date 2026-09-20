#pragma once
// account_repository.hpp
//
// Interface : LoginHandler ne connait que ceci, jamais SQLite directement
// -- remplacer par un backend Postgres/MySQL plus tard (a plus grande
// echelle) n'implique donc de toucher qu'UNE implementation, pas
// LoginHandler ni le protocole SRP6.
//
// Ne stocke JAMAIS de mot de passe : uniquement (salt, verifier) issus de
// security/srp6.hpp::compute_verifier().

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace netsrv::accounts {

struct AccountRecord {
    std::string username;
    std::vector<std::byte> salt;
    std::vector<std::byte> verifier;
};

class AccountRepository {
public:
    virtual ~AccountRepository() = default;

    virtual std::optional<AccountRecord> find(std::string_view username) = 0;

    // false si le compte existe deja (ex: contrainte PRIMARY KEY violee).
    virtual bool create(const AccountRecord& record) = 0;
};

} // namespace netsrv::accounts
