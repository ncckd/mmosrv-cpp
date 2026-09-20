// create_account.cpp
//
// Outil d'administration : cree un compte (salt+verifier SRP6, jamais le
// mot de passe) dans la base SQLite utilisee par Login. Dans un vrai jeu,
// le client calculerait le verifier lui-meme a l'inscription ; "le client
// n'existe pas" ici, donc c'est cet outil qui joue ce role.
//
// Usage:
//   ./netsrv_create_account <db_path> <username> <password>
//   ./netsrv_create_account accounts.db admin "un mot de passe solide"

#include "accounts/sqlite_account_repository.hpp"
#include "security/srp6.hpp"

#include <iostream>
#include <string>

int main(int argc, char** argv) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <db_path> <username> <password>\n";
        return 1;
    }
    const std::string db_path = argv[1];
    const std::string username = argv[2];
    const std::string password = argv[3];

    try {
        netsrv::accounts::SqliteAccountRepository repo(db_path);

        auto reg = netsrv::security::srp6::compute_verifier(username, password);
        netsrv::accounts::AccountRecord record{ username, reg.salt, reg.verifier };

        if (!repo.create(record)) {
            std::cerr << "Echec : le compte '" << username << "' existe deja dans " << db_path << "\n";
            return 1;
        }

        std::cout << "Compte '" << username << "' cree dans " << db_path << ".\n"
                   << "Le mot de passe n'a PAS ete stocke (SRP6 : seuls salt+verifier le sont).\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Erreur: " << e.what() << "\n";
        return 1;
    }
}
