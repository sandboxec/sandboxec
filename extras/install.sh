#!/usr/bin/env sh
set -eu

REPO="${REPO:-sandboxec/sandboxec}"
BINARY_NAME="${BINARY_NAME:-sandboxec}"
INSTALL_DIR="${INSTALL_DIR:-}"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Error: required command not found: $1" >&2
    exit 1
  fi
}

fetch() {
  url="$1"
  out="$2"

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$out"
    return
  fi

  if command -v wget >/dev/null 2>&1; then
    wget -qO "$out" "$url"
    return
  fi

  echo "Error: neither curl nor wget is installed" >&2
  exit 1
}

fetch_text() {
  url="$1"

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url"
    return
  fi

  if command -v wget >/dev/null 2>&1; then
    wget -qO- "$url"
    return
  fi

  echo "Error: neither curl nor wget is installed" >&2
  exit 1
}

map_arch() {
  case "$1" in
    x86_64|amd64) echo "x86_64" ;;
    i386|i486|i586|i686) echo "i386" ;;
    aarch64|arm64) echo "arm64" ;;
    armv5*|armv6*|armv7*|arm) echo "arm" ;;
    mips) echo "mips" ;;
    mipsle) echo "mipsle" ;;
    mips64) echo "mips64" ;;
    mips64le) echo "mips64le" ;;
    ppc64) echo "ppc64" ;;
    ppc64le) echo "ppc64le" ;;
    riscv64) echo "riscv64" ;;
    s390x) echo "s390x" ;;
    loongarch64|loong64) echo "loong64" ;;
    *)
      echo ""
      ;;
  esac
}

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
if [ "$os" != "linux" ]; then
  echo "Error: unsupported OS: $os (only linux binaries are published)" >&2
  exit 1
fi

arch="$(map_arch "$(uname -m)")"
if [ -z "$arch" ]; then
  echo "Error: unsupported architecture: $(uname -m)" >&2
  exit 1
fi

release_api="https://api.github.com/repos/${REPO}/releases/latest"
tag="$(fetch_text "$release_api" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
if [ -z "$tag" ]; then
  echo "Error: failed to resolve latest release tag from ${release_api}" >&2
  exit 1
fi

asset="${BINARY_NAME}_${tag}-linux_${arch}"
url="https://github.com/${REPO}/releases/download/${tag}/${asset}"

# shellcheck disable=SC2039
TMPDIR_BASE="${TMPDIR:-/tmp}"
tmpdir="$(mktemp -d "${TMPDIR_BASE%/}/${BINARY_NAME}.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT INT TERM

bin_path="${tmpdir}/${BINARY_NAME}"
fetch "$url" "$bin_path"
chmod +x "$bin_path"

default_dir="/usr/local/bin"
user_home="${HOME:-}"
if [ -n "$user_home" ]; then
  user_dir="${user_home}/.local/bin"
else
  user_dir="$PWD"
fi
cwd_dir="$PWD"

target_dir="$INSTALL_DIR"
if [ -z "$target_dir" ]; then
  if [ -w "$default_dir" ]; then
    target_dir="$default_dir"
  else
    target_dir="$user_dir"
  fi
fi

install_to_dir() {
  dir="$1"

  if ! mkdir -p "$dir" 2>/dev/null; then
    return 1
  fi

  if ! install -m 0755 "$bin_path" "$dir/$BINARY_NAME" 2>/dev/null; then
    return 1
  fi

  return 0
}

if ! install_to_dir "$target_dir"; then
  if [ -z "$INSTALL_DIR" ] && [ "$target_dir" = "$user_dir" ] && [ "$cwd_dir" != "$user_dir" ]; then
    if install_to_dir "$cwd_dir"; then
      target_dir="$cwd_dir"
      echo "Note: fallback install location used: $target_dir" >&2
    else
      echo "Error: cannot install to default user dir ($user_dir) or current directory ($cwd_dir)" >&2
      echo "Tip: choose a writable path with INSTALL_DIR, e.g. INSTALL_DIR=\"$cwd_dir\"" >&2
      exit 1
    fi
  else
    echo "Error: cannot install to: $target_dir/$BINARY_NAME" >&2
    echo "Tip: choose a writable path with INSTALL_DIR, e.g. INSTALL_DIR=\"$cwd_dir\"" >&2
    exit 1
  fi
fi

echo "Installed at $target_dir/$BINARY_NAME"
if ! printf '%s' ":$PATH:" | grep -q ":$target_dir:"; then
  echo "Note: $target_dir is not in PATH"
fi
