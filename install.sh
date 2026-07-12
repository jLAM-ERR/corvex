#!/bin/sh
# Installs the latest corvex release, and the xray engine binary if missing.
set -eu

CORVEX_REPO="jLAM-ERR/corvex"
XRAY_REPO="XTLS/Xray-core"
INSTALL_DIR="/usr/local/bin"
GEO_ASSET_DIR="/usr/local/share/xray"

err() {
  printf 'Error: %s\n' "$1" >&2
}

warn() {
  printf 'Warning: %s\n' "$1" >&2
}

corvex_manual_hint() {
  printf 'Manual install: download the corvex release for your platform from https://github.com/%s/releases/latest, extract the archive, and copy the "corvex" binary into your PATH (e.g. %s).\n' "$CORVEX_REPO" "$INSTALL_DIR" >&2
}

xray_manual_hint() {
  printf 'Manual install: download the Xray release for your platform from https://github.com/%s/releases/latest, extract the archive, and copy the "xray" binary into your PATH (e.g. %s).\n' "$XRAY_REPO" "$INSTALL_DIR" >&2
}

xray_dat_manual_hint() {
  printf 'Manual install: extract geoip.dat and geosite.dat from the Xray release archive (https://github.com/%s/releases/latest) and copy them into %s (used only when XRAY_LOCATION_ASSET is not already set).\n' "$XRAY_REPO" "$GEO_ASSET_DIR" >&2
}

unsupported_platform() {
  err "unsupported platform: $1"
  err "Build from source instead: cargo build --release (see README)"
  exit 1
}

require_sudo() {
  hint="$1"
  if ! command -v sudo >/dev/null 2>&1; then
    err "sudo is required to write to ${INSTALL_DIR} but was not found"
    "$hint"
    exit 1
  fi
}

install_binary() {
  src="$1"
  name="$2"
  hint="$3"
  dest="${INSTALL_DIR}/${name}"
  if [ ! -d "$INSTALL_DIR" ]; then
    if [ -w "$(dirname "$INSTALL_DIR")" ]; then
      mkdir -p "$INSTALL_DIR"
    else
      require_sudo "$hint"
      sudo mkdir -p "$INSTALL_DIR"
    fi
  fi
  if [ -w "$INSTALL_DIR" ]; then
    install -m 755 "$src" "$dest"
  else
    require_sudo "$hint"
    echo "Root privileges are required to write to ${INSTALL_DIR}; requesting sudo..." >&2
    sudo install -m 755 "$src" "$dest"
  fi
}

# Best-effort install of a geo data file; non-fatal on failure (callers must warn, not exit).
install_dat_file() {
  src="$1"
  name="$2"
  dest="${GEO_ASSET_DIR}/${name}"
  if [ ! -d "$GEO_ASSET_DIR" ]; then
    if [ -w "$(dirname "$GEO_ASSET_DIR")" ]; then
      mkdir -p "$GEO_ASSET_DIR" || return 1
    elif command -v sudo >/dev/null 2>&1; then
      sudo mkdir -p "$GEO_ASSET_DIR" || return 1
    else
      return 1
    fi
  fi
  if [ -w "$GEO_ASSET_DIR" ]; then
    install -m 644 "$src" "$dest" || return 1
  elif command -v sudo >/dev/null 2>&1; then
    sudo install -m 644 "$src" "$dest" || return 1
  else
    return 1
  fi
}

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin)
    case "$ARCH" in
      arm64) XRAY_ASSET="Xray-macos-arm64-v8a.zip" ;;
      x86_64) XRAY_ASSET="Xray-macos-64.zip" ;;
      *) unsupported_platform "macOS architecture ${ARCH} (corvex install.sh supports arm64 and x86_64)" ;;
    esac
    ;;
  Linux)
    case "$ARCH" in
      x86_64) XRAY_ASSET="Xray-linux-64.zip" ;;
      aarch64|arm64) unsupported_platform "Linux aarch64 (corvex does not publish an aarch64 Linux build)" ;;
      *) unsupported_platform "Linux architecture ${ARCH} (corvex install.sh supports x86_64 only)" ;;
    esac
    ;;
  *) unsupported_platform "operating system ${OS} (corvex install.sh supports macOS and Linux only)" ;;
esac

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "Fetching latest corvex release info..."
API_URL="https://api.github.com/repos/${CORVEX_REPO}/releases/latest"
if ! API_RESPONSE="$(curl -fsSL "$API_URL")"; then
  err "failed to reach GitHub API for ${CORVEX_REPO}"
  corvex_manual_hint
  exit 1
fi

TAG="$(printf '%s\n' "$API_RESPONSE" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"
if [ -z "$TAG" ]; then
  err "could not determine latest corvex release tag"
  corvex_manual_hint
  exit 1
fi
VERSION="${TAG#v}"

case "$OS" in
  Darwin) CORVEX_ASSET="corvex-${VERSION}-darwin-universal.tar.gz" ;;
  Linux) CORVEX_ASSET="corvex-${VERSION}-linux-x86_64.tar.gz" ;;
esac

CORVEX_URL="https://github.com/${CORVEX_REPO}/releases/download/${TAG}/${CORVEX_ASSET}"

echo "Downloading ${CORVEX_ASSET} (${TAG})..."
if ! curl -fsSL -o "${WORKDIR}/${CORVEX_ASSET}" "$CORVEX_URL"; then
  err "failed to download ${CORVEX_ASSET} from ${CORVEX_URL}"
  if [ "$OS" = "Linux" ]; then
    err "Linux binaries are published starting v0.6.0. If ${TAG} predates that, build from source instead: cargo build --release (see README)."
  fi
  corvex_manual_hint
  exit 1
fi

if ! curl -fsSL -o "${WORKDIR}/${CORVEX_ASSET}.sha256" "${CORVEX_URL}.sha256"; then
  err "failed to download checksum file ${CORVEX_ASSET}.sha256"
  corvex_manual_hint
  exit 1
fi

echo "Verifying checksum..."
# the .sha256 file embeds the bare archive name, so verification must run from the same directory
if ! ( cd "$WORKDIR" && case "$OS" in
  Darwin) shasum -a 256 -c "${CORVEX_ASSET}.sha256" ;;
  Linux) sha256sum -c "${CORVEX_ASSET}.sha256" ;;
esac ); then
  err "checksum verification failed for ${CORVEX_ASSET}"
  corvex_manual_hint
  exit 1
fi

echo "Extracting ${CORVEX_ASSET}..."
if ! tar -xzf "${WORKDIR}/${CORVEX_ASSET}" -C "$WORKDIR"; then
  err "failed to extract ${CORVEX_ASSET}"
  corvex_manual_hint
  exit 1
fi

CORVEX_BIN="${WORKDIR}/${CORVEX_ASSET%.tar.gz}/corvex"
if [ ! -f "$CORVEX_BIN" ]; then
  err "corvex binary not found in extracted archive"
  corvex_manual_hint
  exit 1
fi

install_binary "$CORVEX_BIN" "corvex" corvex_manual_hint
echo "corvex installed to ${INSTALL_DIR}/corvex (${TAG})"

if command -v xray >/dev/null 2>&1; then
  echo "xray already installed at $(command -v xray); skipping."
else
  if ! command -v unzip >/dev/null 2>&1; then
    err "unzip is required to install xray but was not found"
    err "install unzip via your package manager, then re-run this script"
    xray_manual_hint
    exit 1
  fi

  XRAY_URL="https://github.com/${XRAY_REPO}/releases/latest/download/${XRAY_ASSET}"
  echo "Downloading xray (${XRAY_ASSET})..."
  if ! curl -fsSL -o "${WORKDIR}/${XRAY_ASSET}" "$XRAY_URL"; then
    err "failed to download ${XRAY_ASSET} from ${XRAY_URL}"
    xray_manual_hint
    exit 1
  fi

  echo "Extracting ${XRAY_ASSET}..."
  XRAY_EXTRACT_DIR="${WORKDIR}/xray-extract"
  mkdir -p "$XRAY_EXTRACT_DIR"
  if ! unzip -q -o "${WORKDIR}/${XRAY_ASSET}" -d "$XRAY_EXTRACT_DIR"; then
    err "failed to extract ${XRAY_ASSET}"
    xray_manual_hint
    exit 1
  fi

  XRAY_BIN="${XRAY_EXTRACT_DIR}/xray"
  if [ ! -f "$XRAY_BIN" ]; then
    err "xray binary not found in extracted archive"
    xray_manual_hint
    exit 1
  fi

  install_binary "$XRAY_BIN" "xray" xray_manual_hint
  echo "xray installed to ${INSTALL_DIR}/xray"

  echo "Installing geo data files (geoip.dat, geosite.dat)..."
  GEOIP_FILE="${XRAY_EXTRACT_DIR}/geoip.dat"
  GEOSITE_FILE="${XRAY_EXTRACT_DIR}/geosite.dat"
  if [ -f "$GEOIP_FILE" ] && [ -f "$GEOSITE_FILE" ] \
    && install_dat_file "$GEOIP_FILE" "geoip.dat" \
    && install_dat_file "$GEOSITE_FILE" "geosite.dat"; then
    echo "geo data files installed to ${GEO_ASSET_DIR}"
  else
    warn "failed to install geoip.dat/geosite.dat to ${GEO_ASSET_DIR} (geosite:/geoip: routing rules need XRAY_LOCATION_ASSET set some other way)"
    xray_dat_manual_hint
  fi
fi
