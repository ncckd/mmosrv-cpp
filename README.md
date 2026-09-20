# mmosrv-cpp

A small C++20 framework for TCP/UDP servers: one `Server<Protocol, Role, Handler>` template, thread-per-core, built on Asio coroutines.

```cpp
Server<TcpProtocol, ServerRole::World, MyHandler>    tcp(handler, 8085);
Server<UdpProtocol, ServerRole::World, MyUdpHandler> udp(handler, 8086);
```

Same core for TCP or UDP — just swap the first template argument.
`Role` picks a compile-time config (thread count, buffers, limits) via
`ServerConfig<Role>` specialization.

## Design

- **Thread-per-core, shared-nothing** — each core owns its own
  `io_context` and its own listening socket (`SO_REUSEPORT`); the kernel
  spreads connections across threads, no central acceptor, no lock.
- **C++20 coroutines** (Asio `awaitable<>`) for accept/read loops — no
  callback chains.
- **Concepts** (`SocketProtocol`, `StreamHandler`, `DatagramHandler`)
  constrain what a protocol/handler must provide, checked at compile time.

## Status

Early stage — a seed project for exploring this design, not a hardened
library yet. There's a rougher example on top (multi-process auth flow
with SRP6a, SQLite, service discovery) if you want to see it applied to
something concrete, but the `Server<>` / `Session` core is the point.

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

C++20 compiler, CMake ≥ 3.20. Asio (standalone) fetched automatically.