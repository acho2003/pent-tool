#!/bin/sh
set -eu

if [ "$#" -eq 0 ]; then
    echo "usage: XALGORIX_SOURCE_DIR=/absolute/path runtime/source-compose.sh <compose command>" >&2
    exit 2
fi

case "${XALGORIX_SOURCE_DIR:-}" in
    /*) ;;
    *) echo "XALGORIX_SOURCE_DIR must be an absolute directory" >&2; exit 2 ;;
esac
if [ ! -d "$XALGORIX_SOURCE_DIR" ]; then
    echo "XALGORIX_SOURCE_DIR does not exist" >&2
    exit 2
fi

for arg do
    case "$arg" in
        build|pull|push|--build|--pull|--pull=*|-f|--file|--file=*)
            echo "image building and pulling are disabled in this workflow" >&2
            exit 2
            ;;
    esac
done

exec docker compose -f "$(dirname "$0")/../compose.source.yaml" "$@"
