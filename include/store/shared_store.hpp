#pragma once
// shared_store.hpp
//
// Magasin cle/valeur en memoire, avec expiration (TTL), thread-safe. Vit
// dans le processus Master (voir handlers/master_handler.hpp + main.cpp)
// et sert a la fois :
//   - aux tickets emis par Master (securisent l'acces a Login)
//   - aux jetons de session emis par Login (lus par World)
//
// Frequence d'acces : une poignee d'operations par connexion CLIENT (au
// moment de l'auth), PAS par paquet de gameplay -- std::shared_mutex
// (lectures concurrentes, ecriture exclusive) est donc largement
// suffisant. Pas besoin d'une structure lock-free ici : la simplicite et
// la correction priment sur la micro-perf pour ce chemin froid.

#include <chrono>
#include <cstddef>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace netsrv::store {

class SharedStore {
public:
    // Ecrit (ou remplace) une entree, valide pendant `ttl`.
    void put(std::string key, std::vector<std::byte> value, std::chrono::seconds ttl) {
        std::unique_lock lock(mutex_);
        entries_.insert_or_assign(std::move(key),
            Entry{std::move(value), std::chrono::steady_clock::now() + ttl});
    }

    // Lecture simple, sans consommer l'entree.
    std::optional<std::vector<std::byte>> get(const std::string& key) {
        std::shared_lock lock(mutex_);
        auto it = entries_.find(key);
        if (it == entries_.end() || is_expired(it->second)) return std::nullopt;
        return it->second.value;
    }

    // Lecture + suppression ATOMIQUE : c'est ce qui rend un jeton a usage
    // unique (ticket Master, jeton de session Login) impossible a
    // rejouer -- une fois "take", une 2e tentative ne trouve plus rien,
    // meme si elle arrive une microseconde apres.
    std::optional<std::vector<std::byte>> take(const std::string& key) {
        std::unique_lock lock(mutex_);
        auto it = entries_.find(key);
        if (it == entries_.end() || is_expired(it->second)) return std::nullopt;
        auto value = std::move(it->second.value);
        entries_.erase(it);
        return value;
    }

    // A appeler periodiquement (voir main.cpp) pour liberer la memoire des
    // entrees expirees jamais consommees (client qui obtient un ticket
    // puis abandonne, par exemple).
    std::size_t sweep_expired() {
        std::unique_lock lock(mutex_);
        std::size_t removed = 0;
        for (auto it = entries_.begin(); it != entries_.end();) {
            if (is_expired(it->second)) { it = entries_.erase(it); ++removed; }
            else ++it;
        }
        return removed;
    }

    // Toutes les entrees dont la cle commence par `prefix`, non expirees.
    // Utilise pour le REGISTRE de services (voir registry/world_registry.hpp) :
    // "donne-moi tous les World actuellement enregistres", par exemple.
    std::vector<std::pair<std::string, std::vector<std::byte>>> list_prefix(const std::string& prefix) {
        std::shared_lock lock(mutex_);
        std::vector<std::pair<std::string, std::vector<std::byte>>> out;
        for (const auto& [key, entry] : entries_) {
            if (is_expired(entry)) continue;
            if (key.compare(0, prefix.size(), prefix) == 0) out.emplace_back(key, entry.value);
        }
        return out;
    }

    std::size_t size() const {
        std::shared_lock lock(mutex_);
        return entries_.size();
    }

private:
    struct Entry {
        std::vector<std::byte> value;
        std::chrono::steady_clock::time_point expires_at;
    };
    static bool is_expired(const Entry& e) {
        return std::chrono::steady_clock::now() >= e.expires_at;
    }

    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, Entry> entries_;
};

} // namespace netsrv::store
