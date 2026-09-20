# netsrv — framework de serveurs TCP/UDP en C++20

`Server<Protocol, Role, Handler>` — thread-per-core, shared-nothing —
avec cette fois : **le trou de redirection Master→Login comblé**, un
**registre de services auto-nettoyant** (Login/World s'annoncent par
heartbeat), et un **système de login complet** : SQLite + SRP6a (via
OpenSSL BIGNUM) + résistance à l'énumération de comptes + liste des
mondes en ligne.

## Le trou comblé : comment Master indique le Login au client

Avant, Master renvoyait un ticket sans jamais dire **où** l'utiliser.
Maintenant Master **lit le registre de services** (alimenté par le
heartbeat de chaque instance Login, voir plus bas) et répond avec
`{ticket, login_host, login_port}` (`net/master_protocol.hpp`). Sans
Login disponible dans le registre → réponse d'erreur générique.

## Flux complet

```
Client -> Master  : "hello"
Master -> Client  : {ticket, login_host, login_port}   (registry::pick_login, en memoire)
Client -> Login   : ClientHello{ticket, username}
Login  -> Store   : take(ticket)  [reseau, HMAC]         -- invalide/rejoue => connexion fermee
Login  -> DB      : find(username)  [SQLite]              -- compte existant OU non (indistinguable ensuite)
Login  -> Client  : ServerChallenge{salt, B}               (SRP6a)
Client -> Login   : ClientProof{A, M1}
Login  (verifie M1, cote serveur, SRP6a)
Login  -> Client  : ServerProof{M2, session_token} + WorldList
Login  -> Store   : put(session_token, username, ttl)    [reseau, HMAC]
                     (worlds lus via list_prefix("registry:world:"))
```

En parallele, en tache de fond :
```
Login  -> Store : heartbeat "registry:login:<host:port>"  toutes les 5s (TTL 15s)
World  -> Store : heartbeat "registry:world:<host:port>"  toutes les 5s (TTL 15s, POPULATION reelle)
```
Si un process meurt, son entree expire d'elle-meme au bout de 15s max :
aucun protocole de detection de panne separe a maintenir.

## SRP6a : ce qui a ete generé, vérifié, et testé

**Le groupe** (nombre premier "sûr" 2048 bits) a été **généré et vérifié
premier dans ce sandbox** via `BN_generate_prime_ex(..., safe=1)` +
`BN_check_prime()` indépendant — jamais recopié de mémoire, pour éliminer
tout risque de transcription sur une constante de sécurité. Vérification
programmatique (pas à l'œil) que la valeur intégrée dans `srp6.hpp`
correspond bit-exact à la valeur générée.

**Propriété centrale de SRP6a** : le mot de passe n'est **jamais**
transmis sur le réseau, ni stocké côté serveur — seuls `(salt, verifier)`
le sont. `security/srp6.hpp` implémente les deux côtés (serveur *et*
client, ce dernier pour `tools/client_sim.cpp` puisque "le client
n'existe pas").

**Résistance à l'énumération de comptes** (`login_handler.hpp`) : si le
username n'existe pas, un challenge *factice mais indistinguable* est
généré (salt dérivé de façon déterministe par HMAC du username, verifier
aléatoire) — la vérification échoue ensuite exactement comme pour un
*mauvais mot de passe sur un compte réel*, avec la même réponse. Un
attaquant ne peut pas distinguer les deux cas.

**Testé réellement** (compilé + lié + exécuté dans ce sandbox, via les
en-têtes OpenSSL embarqués par Node.js + `libcrypto.so.3` du système) :
- handshake nominal : le client et le serveur dérivent **exactement** la
  même clé de session K, la preuve mutuelle M1/M2 passe des deux côtés ;
- mauvais mot de passe → rejeté ;
- `A ≡ 0 (mod N)` → rejeté immédiatement (garde-fou anti-triche classique
  de SRP, sans même évaluer la preuve) ;
- rejeu d'une preuve calculée pour un autre challenge → rejeté.

## SQLite (comptes) : bug réel trouvé et corrigé en testant

`accounts/sqlite_account_repository.hpp` : **une connexion SQLite PAR
THREAD** (`thread_local`, cohérent avec le reste de l'architecture
shared-nothing) plutôt qu'une connexion partagée + mutex.

Premier jet testé avec 8 threads créant chacun un compte en parallèle :
**crash** (`SQLITE_BUSY` non géré → exception → `std::terminate` dans un
thread). Cause : plusieurs connexions séparées vers le même fichier, sans
mode WAL ni `busy_timeout`, se bloquent mutuellement sous écriture
concurrente par défaut. **Corrigé** en activant `PRAGMA
journal_mode=WAL` + `sqlite3_busy_timeout(5000)` à l'ouverture de chaque
connexion — recommandation standard SQLite dès qu'on a plusieurs
connexions concurrentes. Retesté : 8/8 threads OK.

Note technique : `libsqlite3-dev` n'était pas installable dans ce
sandbox (pas de réseau) — `accounts/sqlite3_capi.h` déclare donc à la
main le sous-ensemble stable de l'API C SQLite utilisé (ABI documentée
stable depuis des années). **Chez vous, avec `libsqlite3-dev` installé,
vous pouvez remplacer ce header par le vrai `<sqlite3.h>`** sans rien
changer d'autre — le commentaire en tête de fichier le rappelle.

## Les deux outils

```bash
# Cree un compte (calcule salt+verifier SRP6, le mot de passe n'est jamais stocke)
./netsrv_create_account accounts.db admin "un mot de passe solide"

# Simule un client : Master -> redirection -> Login (SRP6a complet) -> liste des mondes
./netsrv_client_sim 127.0.0.1 3724 admin "un mot de passe solide"
```

`create_account` a été **testé réellement** (création, rejet de doublon).
`client_sim` est écrit sur les mêmes briques testées (protocole,
SRP6 côté client) mais son exécution bout-en-bout nécessite Asio, donc
n'a pas pu tourner ici (voir section suivante).

## Build & lancement (3 process)

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j

export NETSRV_INTERNAL_SECRET=$(openssl rand -hex 32)

./build/netsrv_create_account accounts.db admin "un mot de passe solide"

./build/netsrv_demo --role=master &
./build/netsrv_demo --role=login  --accounts-db=accounts.db &
./build/netsrv_demo --role=world  --world-name=Azshara &

sleep 6   # laisser le temps au 1er heartbeat Login/World d'atteindre Master
./build/netsrv_client_sim 127.0.0.1 3724 admin "un mot de passe solide"
```

Dépendances supplémentaires par rapport à la version précédente :
**SQLite3** (`libsqlite3-dev` recommandé, sinon le shim maison suffit à
compiler contre la lib déjà présente sur la plupart des systèmes Linux).

## Ce qui a été réellement vérifié dans ce sandbox (mise à jour)

✅ **Compilé, lié et exécuté, assertions qui passent** :
- `security/srp6.hpp` : handshake complet + 3 cas négatifs (voir ci-dessus).
- `accounts/sqlite_account_repository.hpp` : create/find/doublon/8 threads
  concurrents (après correctif WAL, cf. ci-dessus).
- `net/login_protocol.hpp`, `net/master_protocol.hpp` : round-trip de
  tous les types de message (ClientHello, ClientProof, ServerChallenge,
  ServerProof, WorldList, redirect Master).
- `store/store_wire.hpp` : `ListPrefix`/`List` (nouveau) en plus des
  tests HMAC/PUT/TAKE déjà valides précédemment.
- `store/shared_store.hpp` : `list_prefix()` (nouveau).
- `tools/create_account.cpp` : exécuté réellement (création + rejet doublon).
- `security/hmac.hpp` : toujours conforme au vecteur RFC 4231.
- Équilibre des accolades vérifié sur les ~30 fichiers du projet.

⚠️ **Non compilable ici (Asio introuvable sans réseau)**, mais écrit sur
des briques déjà toutes testées individuellement :
- `session.hpp`, `server.hpp` (inchangés depuis la 1ère version)
- `handlers/master_handler.hpp`, `login_handler.hpp`, `world_handler.hpp`
- `store/store_handler.hpp`, `store/store_client.hpp`
- `registry/world_registry.hpp` (heartbeat/list en coroutine)
- `tools/client_sim.cpp`, `src/main.cpp`

**Compilez et testez chez vous avant toute mise en prod.**
`-Wall -Wextra` deja actif dans le `CMakeLists.txt`.

## Limitations connues (nouvelles, en plus de celles deja notees)

- **Pas de TLS** sur le canal Login<->Client : SRP6a protege le mot de
  passe et authentifie mutuellement les 2 parties, mais n'apporte PAS la
  confidentialite du reste de l'echange (session_token, liste des mondes
  visibles en clair sur le reseau). Ajoutez TLS par-dessus en prod.
- **M1/M2 simplifies** par rapport a la formule exacte RFC 5054 (voir
  commentaire en tete de `srp6.hpp`) -- le coeur cryptographique (echange
  Diffie-Hellman aveugle via le verifier) reste fidele a SRP6a.
- **`registry::pick_login`** choisit toujours le premier Login trouve --
  pas de vrai equilibrage de charge (TODO signale dans le code).
- **`SqliteAccountRepository`** suppose une seule instance par process
  (vrai ici) a cause du cache `thread_local` de connexions.
- **Pas de verrouillage de compte** apres N echecs de mot de passe (a
  ajouter si vous voulez vous proteger du brute-force en ligne, en plus
  du cout intrinseque des exponentiations modulaires SRP6a qui ralentit
  deja naturellement chaque tentative).
# mmosrv-cpp
# mmosrv-cpp
# mmosrv-cpp
