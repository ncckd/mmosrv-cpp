#pragma once
// sqlite3_capi.h
//
// Declarations minimales de l'API C de SQLite3 utilisees par
// sqlite_account_repository.hpp. NORMALEMENT vous devriez simplement
// #include <sqlite3.h> apres avoir installe libsqlite3-dev -- ce fichier
// n'existe que parce que ce sandbox de generation n'a pas de gestionnaire
// de paquets fonctionnel (pas d'acces reseau) alors que la bibliotheque
// d'execution (libsqlite3.so.0) EST presente, ce qui a permis de compiler
// ET d'executer reellement les tests de account_repository.
//
// Ces signatures sont celles de l'ABI C stable de SQLite (garantie de
// compatibilite ascendante documentee par le projet SQLite depuis des
// annees) : remplacez ce fichier par le vrai <sqlite3.h> des que
// libsqlite3-dev est installe chez vous -- ne PAS garder ce fichier en
// prod par confort.

extern "C" {

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
typedef long long sqlite3_int64;
typedef void (*sqlite3_destructor_type)(void*);

#define SQLITE_OK 0
#define SQLITE_ROW 100
#define SQLITE_DONE 101

#define SQLITE_OPEN_READWRITE 0x00000002
#define SQLITE_OPEN_CREATE    0x00000004

#define SQLITE_TRANSIENT ((sqlite3_destructor_type)-1)

int sqlite3_open_v2(const char* filename, sqlite3** ppDb, int flags, const char* zVfs);
int sqlite3_close(sqlite3*);
int sqlite3_busy_timeout(sqlite3*, int ms);

int sqlite3_exec(sqlite3*, const char* sql,
                  int (*callback)(void*, int, char**, char**),
                  void* arg, char** errmsg);
void sqlite3_free(void*);

int sqlite3_prepare_v2(sqlite3* db, const char* zSql, int nByte,
                        sqlite3_stmt** ppStmt, const char** pzTail);

int sqlite3_bind_text(sqlite3_stmt*, int idx, const char*, int n, sqlite3_destructor_type);
int sqlite3_bind_blob(sqlite3_stmt*, int idx, const void*, int n, sqlite3_destructor_type);
int sqlite3_bind_int64(sqlite3_stmt*, int idx, sqlite3_int64);

int sqlite3_step(sqlite3_stmt*);
const void* sqlite3_column_blob(sqlite3_stmt*, int iCol);
int sqlite3_column_bytes(sqlite3_stmt*, int iCol);
sqlite3_int64 sqlite3_column_int64(sqlite3_stmt*, int iCol);

int sqlite3_finalize(sqlite3_stmt*);
const char* sqlite3_errmsg(sqlite3*);

} // extern "C"
