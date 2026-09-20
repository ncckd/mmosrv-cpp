#pragma once
// sqlite_account_repository.hpp
//
// Implementation SQLite de AccountRepository. UNE CONNEXION PAR THREAD
// (thread_local, ouverte a la demande) plutot qu'une connexion partagee
// avec mutex interne : coherent avec le reste de l'architecture
// shared-nothing (server.hpp, WorldHandler), et evite toute contention
// sur le verrou interne de SQLite puisque chaque thread ne touche jamais
// que SA PROPRE connexion.
//
// Toutes les requetes utilisent des PREPARED STATEMENTS avec parametres
// lies (jamais de concatenation de chaines dans du SQL) : c'est ce qui
// protege contre l'injection SQL, quelle que soit la valeur du username.
//
// Limite assumee : cette classe suppose une SEULE instance par process
// (vrai ici : un LoginHandler, un AccountRepository). Plusieurs instances
// sur le meme thread partageraient a tort leur connexion thread_local si
// cette hypothese changeait -- a corriger (cle par `this`) si besoin.

#include "accounts/account_repository.hpp"
#include "accounts/sqlite3_capi.h"

#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>

namespace netsrv::accounts {

class SqliteAccountRepository : public AccountRepository {
public:
    explicit SqliteAccountRepository(std::string db_path) : db_path_(std::move(db_path)) {
        exec(connection(),
             "CREATE TABLE IF NOT EXISTS accounts ("
             "username TEXT PRIMARY KEY,"
             "salt BLOB NOT NULL,"
             "verifier BLOB NOT NULL,"
             "created_at INTEGER NOT NULL)");
    }

    std::optional<AccountRecord> find(std::string_view username) override {
        auto& db = connection();
        sqlite3_stmt* raw = nullptr;
        if (sqlite3_prepare_v2(&db, "SELECT salt, verifier FROM accounts WHERE username = ?1",
                                -1, &raw, nullptr) != SQLITE_OK)
            throw std::runtime_error(std::string("sqlite prepare (find): ") + sqlite3_errmsg(&db));
        StmtGuard stmt(raw);

        sqlite3_bind_text(stmt.get(), 1, username.data(), static_cast<int>(username.size()), SQLITE_TRANSIENT);
        if (sqlite3_step(stmt.get()) != SQLITE_ROW) return std::nullopt;

        AccountRecord rec;
        rec.username = std::string(username);
        rec.salt     = column_bytes(stmt.get(), 0);
        rec.verifier = column_bytes(stmt.get(), 1);
        return rec;
    }

    bool create(const AccountRecord& record) override {
        auto& db = connection();
        sqlite3_stmt* raw = nullptr;
        if (sqlite3_prepare_v2(&db,
                "INSERT INTO accounts (username, salt, verifier, created_at) VALUES (?1, ?2, ?3, ?4)",
                -1, &raw, nullptr) != SQLITE_OK)
            throw std::runtime_error(std::string("sqlite prepare (create): ") + sqlite3_errmsg(&db));
        StmtGuard stmt(raw);

        sqlite3_bind_text(stmt.get(), 1, record.username.data(), static_cast<int>(record.username.size()), SQLITE_TRANSIENT);
        sqlite3_bind_blob(stmt.get(), 2, record.salt.data(), static_cast<int>(record.salt.size()), SQLITE_TRANSIENT);
        sqlite3_bind_blob(stmt.get(), 3, record.verifier.data(), static_cast<int>(record.verifier.size()), SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt.get(), 4, static_cast<sqlite3_int64>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()));

        // PRIMARY KEY violee (compte deja existant) => step() != SQLITE_DONE => false.
        return sqlite3_step(stmt.get()) == SQLITE_DONE;
    }

private:
    struct DbCloser   { void operator()(sqlite3* db) const { if (db) sqlite3_close(db); } };
    struct StmtCloser { void operator()(sqlite3_stmt* s) const { if (s) sqlite3_finalize(s); } };
    using DbHandle  = std::unique_ptr<sqlite3, DbCloser>;
    using StmtGuard = std::unique_ptr<sqlite3_stmt, StmtCloser>;

    static std::vector<std::byte> column_bytes(sqlite3_stmt* stmt, int col) {
        const auto* ptr = static_cast<const std::byte*>(sqlite3_column_blob(stmt, col));
        const int len = sqlite3_column_bytes(stmt, col);
        return std::vector<std::byte>(ptr, ptr + len);
    }

    static void exec(sqlite3& db, const char* sql) {
        char* err = nullptr;
        if (sqlite3_exec(&db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
            std::string msg = err ? err : "erreur inconnue";
            sqlite3_free(err);
            throw std::runtime_error("sqlite3_exec: " + msg);
        }
    }

    sqlite3& connection() {
        thread_local DbHandle db = open();
        return *db;
    }

    DbHandle open() const {
        sqlite3* raw = nullptr;
        int rc = sqlite3_open_v2(db_path_.c_str(), &raw,
                                  SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
        DbHandle handle(raw, DbCloser{});
        if (rc != SQLITE_OK || !handle)
            throw std::runtime_error("sqlite3_open_v2 a echoue pour " + db_path_);

        // Indispensable des qu'on a PLUSIEURS connexions (une par thread,
        // par design) vers le MEME fichier :
        //  - WAL : les lecteurs ne bloquent jamais les ecrivains et
        //    inversement (bien meilleure concurrence que le journal
        //    "rollback" par defaut, qui prend un verrou exclusif pour
        //    ecrire). Recommandation standard SQLite pour tout usage non
        //    trivialement mono-connexion.
        //  - busy_timeout : si malgre tout deux ecritures se percutent
        //    (WAL n'elimine pas la contention ecrivain-ecrivain), on
        //    RE-ESSAIE automatiquement pendant 5s au lieu de renvoyer
        //    SQLITE_BUSY immediatement.
        sqlite3_busy_timeout(handle.get(), 5000);
        exec(*handle, "PRAGMA journal_mode=WAL");

        return handle;
    }

    std::string db_path_;
};

} // namespace netsrv::accounts
