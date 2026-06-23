#!/bin/sh
# envo installer - downloads the latest prebuilt binary for your platform.
#
#   curl -fsSL https://raw.githubusercontent.com/horiastanxd/envo/main/install.sh | sh
#
# Env overrides:
#   ENVO_VERSION=v0.1.0          install a specific tag (default: latest)
#   ENVO_BIN_DIR=~/.local/bin    install location

set -eu

REPO="horiastanxd/envo"
BIN="envo"

info() { printf '%s\n' "$*" >&2; }
err() { printf 'error: %s\n' "$*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || err "curl is required"
command -v tar >/dev/null 2>&1 || err "tar is required"

os=$(uname -s)
arch=$(uname -m)

case "$os" in
  Linux) os_part="unknown-linux-musl" ;;
  Darwin) os_part="apple-darwin" ;;
  *) err "unsupported OS '$os' - try: cargo install envo-cli" ;;
esac

case "$arch" in
  x86_64 | amd64) arch_part="x86_64" ;;
  aarch64 | arm64) arch_part="aarch64" ;;
  *) err "unsupported architecture '$arch' - try: cargo install envo-cli" ;;
esac

target="${arch_part}-${os_part}"

version="${ENVO_VERSION:-}"
if [ -z "$version" ]; then
  version=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -n1 | cut -d'"' -f4)
  [ -n "$version" ] || err "could not determine latest version"
fi

asset="${BIN}-${target}.tar.gz"
url="https://github.com/${REPO}/releases/download/${version}/${asset}"

bin_dir="${ENVO_BIN_DIR:-}"
if [ -z "$bin_dir" ]; then
  if [ -w "/usr/local/bin" ] 2>/dev/null; then
    bin_dir="/usr/local/bin"
  else
    bin_dir="$HOME/.local/bin"
  fi
fi
mkdir -p "$bin_dir"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

info "Downloading ${BIN} ${version} (${target})..."
curl -fsSL "$url" -o "$tmp/$asset" || err "download failed: $url"
tar -xzf "$tmp/$asset" -C "$tmp"
chmod +x "$tmp/$BIN"
mv "$tmp/$BIN" "$bin_dir/$BIN"

info "Installed to ${bin_dir}/${BIN}"
case ":$PATH:" in
  *":$bin_dir:"*) ;;
  *) info "Note: add ${bin_dir} to your PATH." ;;
esac
info "Run: ${BIN} --help"
