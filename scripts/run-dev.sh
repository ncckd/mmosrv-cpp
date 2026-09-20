#!/usr/bin/env bash

set -e

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="$ROOT/build/netsrv_demo"

if [ ! -f "$BINARY" ]; then
    echo "ERROR: $BINARY does not exist."
    echo "Run the build first."
    exit 1
fi

if [ -f "$ROOT/.env" ]; then
    set -a
    source "$ROOT/.env"
    set +a
fi

SERVERS=(
    master
    login
)

case "$1" in

    master|login)
        exec "$BINARY" --role="$1"
        ;;

    all)
        echo "Starting MMO servers..."

        for server in "${SERVERS[@]}"; do
            echo "Starting $server..."
            "$BINARY" "$server" &
        done

        echo
        echo "All MMO servers started."
        echo "Press Ctrl+C to stop all servers."

        trap 'kill 0' SIGINT SIGTERM

        wait
        ;;

    *)
        echo "Usage:"
        echo "  $0 master"
        echo "  $0 login"
        echo "  $0 all"
        exit 1
        ;;

esac