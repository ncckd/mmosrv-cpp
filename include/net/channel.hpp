#pragma once
// channel.hpp
//
// Dispatch de paquets par "header" (opcode) vers une fonction membre,
// enregistree une seule fois dans une table statique. Utilise a la fois
// pour le gameplay (handlers/player_channel.hpp) et implicitement inspire
// ce que fait store/store_handler.hpp pour le protocole interne.
//
// Par rapport au pattern habituel :
//
//     if (m_handlers.size() == 0) {
//         m_handlers[OPCODE] = &Class::fn;
//         ...
//     }
//
// ce mixin corrige une race condition latente : sur un serveur
// thread-per-core (voir server.hpp), plusieurs threads peuvent traiter
// leur PREMIER paquet en meme temps -> plusieurs threads peuvent observer
// size()==0 simultanement et remplir la map EN PARALLELE. Resultat
// possible : corruption de std::unordered_map (comportement indefini),
// ou dispatch vers une table partiellement construite. Plus c'est rare a
// declencher (seulement au tout premier paquet de chaque role), plus
// c'est le genre de bug qui ne sort jamais en test et arrive en prod un
// jour de forte charge.
//
// Le correctif standard depuis C++11 : une variable statique LOCALE A UNE
// FONCTION est garantie initialisee exactement une fois, meme sous
// contention multi-thread ("magic statics" / initialisation thread-safe
// au premier usage, cf. [stmt.dcl]p4 du standard). Le compilateur genere
// un garde (verification atomique, tres bon marche) sans qu'on ecrive de
// mutex ni de std::call_once explicite -- c'est litteralement le meme
// mecanisme que std::call_once, integre au langage.

#include <asio.hpp>

#include <cstdint>
#include <span>
#include <unordered_map>

namespace netsrv {

// Derived doit fournir : static HandlerMap build_handlers();
// (une fonction appelee UNE seule fois, qui construit la table
// {opcode -> fonction membre}).
template <typename Derived, typename SessionT>
class Channel {
public:
    using Opcode     = std::uint16_t;
    using HandlerFn  = asio::awaitable<void> (Derived::*)(SessionT&, std::span<const std::byte>);
    using HandlerMap = std::unordered_map<Opcode, HandlerFn>;

    // Dispatch vers la fonction enregistree pour cet opcode. `body` est le
    // payload APRES l'opcode (les 2 premiers octets deja consommes par
    // l'appelant, cf. handlers/world_handler.hpp). Un opcode inconnu est
    // ignore silencieusement (no-op) : un paquet malforme ou d'une
    // version client differente ne doit jamais faire planter un thread
    // I/O entier -- c'est la meme philosophie "fail safe" que le reste
    // du framework (voir le try/catch de Session::run()).
    asio::awaitable<void> dispatch(SessionT& session, Opcode opcode, std::span<const std::byte> body) {
        const auto& map = handlers();
        auto it = map.find(opcode);
        if (it == map.end()) co_return;
        co_await (static_cast<Derived*>(this)->*(it->second))(session, body);
    }

    static bool has_handler(Opcode opcode) { return handlers().contains(opcode); }

private:
    // "Magic static" : thread-safe des le premier appel concurrent, cout
    // nul ensuite (juste une lecture, aucun verrou retenu apres init).
    static const HandlerMap& handlers() {
        static const HandlerMap map = Derived::build_handlers();
        return map;
    }
};

// Piste d'optimisation supplementaire (non appliquee ici pour garder le
// cas general simple) : si vos opcodes sont des petits entiers denses
// (0..N-1, N connu a la compilation), remplacez HandlerMap par
// `std::array<HandlerFn, N>` initialise a nullptr. Le dispatch devient un
// acces indexe direct (une vraie "jump table"), sans hachage ni
// recherche -- plus rapide que l'unordered_map ci-dessus si vous dispatchez
// des dizaines de milliers de paquets/seconde. Le reste du mixin (magic
// static, dispatch()) reste identique ; seul le type retourne par
// handlers() change.

} // namespace netsrv
