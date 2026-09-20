cmake_minimum_required(VERSION 3.20)
project(netsrv LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED) # HMAC (EVP_MAC) + RAND_bytes -- voir include/security/

# SQLite3 : find_library (pas find_package(SQLite3)) car
# accounts/sqlite3_capi.h declare lui-meme le sous-ensemble d'API utilise
# (voir ce fichier : le sandbox de generation n'avait pas libsqlite3-dev,
# seule la bibliotheque d'execution). Si vous avez libsqlite3-dev
# installe, vous pouvez remplacer ce header par le vrai <sqlite3.h> --
# find_library() fonctionne dans les deux cas.
find_library(SQLITE3_LIB sqlite3 REQUIRED)

# --- Asio (standalone, header-only) -----------------------------------------
# Par defaut : telechargee via FetchContent.
# Si vous avez deja Asio (vcpkg/conan/systeme) ou preferez Boost.Asio, passez
# -DNETSRV_ASIO_INCLUDE_DIR=/chemin/vers/asio/include et adaptez les
# `#include <asio.hpp>` -> `#include <boost/asio.hpp>` + namespace si besoin.
if(NOT NETSRV_ASIO_INCLUDE_DIR)
    include(FetchContent)
    FetchContent_Declare(
        asio
        GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
        GIT_TAG asio-1-30-2
    )
    FetchContent_MakeAvailable(asio)
    set(NETSRV_ASIO_INCLUDE_DIR "${asio_SOURCE_DIR}/asio/include")
endif()

add_library(asio_headers INTERFACE)
target_include_directories(asio_headers INTERFACE ${NETSRV_ASIO_INCLUDE_DIR})
target_compile_definitions(asio_headers INTERFACE ASIO_STANDALONE ASIO_NO_DEPRECATED)

add_executable(netsrv_demo src/main.cpp)
target_include_directories(netsrv_demo PRIVATE include)
target_link_libraries(netsrv_demo PRIVATE asio_headers Threads::Threads OpenSSL::Crypto ${SQLITE3_LIB})

add_executable(netsrv_create_account tools/create_account.cpp)
target_include_directories(netsrv_create_account PRIVATE include)
target_link_libraries(netsrv_create_account PRIVATE OpenSSL::Crypto ${SQLITE3_LIB})

add_executable(netsrv_client_sim tools/client_sim.cpp)
target_include_directories(netsrv_client_sim PRIVATE include)
target_link_libraries(netsrv_client_sim PRIVATE asio_headers Threads::Threads OpenSSL::Crypto)

foreach(tgt netsrv_demo netsrv_create_account netsrv_client_sim)
    target_compile_options(${tgt} PRIVATE $<$<CXX_COMPILER_ID:GNU,Clang>:-O3 -Wall -Wextra>)
endforeach()

# Astuce perf (a verifier selon votre version d'Asio) : sur Linux avec
# liburing installee, des versions recentes d'Asio (>= 1.22) peuvent utiliser
# io_uring comme backend reactor a la place d'epoll pour un throughput
# superieur a tres grande echelle. Les flags exacts varient selon la version
# d'Asio -- consultez sa documentation / son changelog avant d'activer ceci
# en production. Non active ici par defaut pour rester portable.
