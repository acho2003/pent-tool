#!/bin/bash
# Xalgorix Build Script

set -e

cd "$(dirname "$0")"

# Extract version from Makefile
VERSION=$(grep '^VERSION=' Makefile | cut -d'=' -f2)

echo "Building Xalgorix v${VERSION}..."

# Build with version injected via ldflags + output as release binary name
go build -ldflags "-s -w -X main.version=${VERSION}" -buildvcs=false -o xalgorix-linux-amd64 ./cmd/xalgorix/

# Also create a local copy
cp xalgorix-linux-amd64 xalgorix

echo "Build successful: xalgorix v${VERSION}"

if [ "$1" = "--install" ] || [ "$1" = "-i" ]; then
    echo "Installing to /usr/local/bin..."
    sudo cp xalgorix-linux-amd64 /usr/local/bin/xalgorix
    echo "Installed!"
fi
