#!/usr/bin/env sh
# Baut PassMind für alle Plattformen nach ./dist (benötigt Go, siehe go.mod).
set -e
VERSION="${VERSION:-$(git describe --tags --always 2>/dev/null || echo dev)}"
mkdir -p dist
for target in windows/amd64 windows/arm64 darwin/amd64 darwin/arm64 linux/amd64 linux/arm64; do
  os="${target%/*}"; arch="${target#*/}"
  out="dist/passmind-${os}-${arch}"
  [ "$os" = windows ] && out="$out.exe"
  echo "-> $out"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$out" .
done
