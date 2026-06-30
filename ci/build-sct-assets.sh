#!/usr/bin/env bash
# Build/download UEFI SCT smoke-test assets for CrabEFI CI.
#
# This script intentionally consumes upstream prebuilt public artifacts instead
# of building EDK2/SCT in CI:
#   - tianocore/edk2-test UEFI SCT package
#   - pbatard/UEFI-Shell EDK2 shell binary

set -euo pipefail

ARCH="x86_64"
OUT_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --arch)
      ARCH="$2"
      shift 2
      ;;
    --output|--out-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    -h|--help)
      cat <<'USAGE'
Usage: ci/build-sct-assets.sh [--arch x86_64] [--output DIR]

Downloads and verifies the prebuilt UEFI SCT package and EDK2 UEFI Shell used by
`./crabefi test --app uefi-sct-smoke`.
USAGE
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ "$ARCH" != "x86_64" ]]; then
  echo "Only --arch x86_64 is currently supported for UEFI SCT smoke assets" >&2
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/sct-assets/$ARCH}"
mkdir -p "$OUT_DIR"

SCT_RELEASE="edk2-test-stable202509"
SCT_ARCHIVE="SctPackageX64.7z"
SCT_URL="https://github.com/tianocore/edk2-test/releases/download/$SCT_RELEASE/$SCT_ARCHIVE"
SCT_SHA256="0565fa59b608b7281e9d7da1c1a25713b98def85d0a8f57a31ce0b959b064d06"

SHELL_RELEASE="26H1"
SHELL_FILE="shellx64.efi"
SHELL_URL="https://github.com/pbatard/UEFI-Shell/releases/download/$SHELL_RELEASE/$SHELL_FILE"
SHELL_SHA256="4ea080ddd576117cd04f5c02d16712ea5d9249c0752214d8e4055e460d7b11e0"

need_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required tool: $1" >&2
    echo "Install it with nix develop, or on Ubuntu: sudo apt-get install curl p7zip-full" >&2
    exit 1
  fi
}

need_tool curl
need_tool sha256sum
need_tool 7z

download_if_needed() {
  local url="$1"
  local dest="$2"
  local sha="$3"

  if [[ -f "$dest" ]] && echo "$sha  $dest" | sha256sum -c >/dev/null 2>&1; then
    echo "Using cached $(basename "$dest")"
    return
  fi

  echo "Downloading $url"
  curl -L --retry 3 --fail -o "$dest.tmp" "$url"
  echo "$sha  $dest.tmp" | sha256sum -c
  mv "$dest.tmp" "$dest"
}

download_if_needed "$SHELL_URL" "$OUT_DIR/$SHELL_FILE" "$SHELL_SHA256"
download_if_needed "$SCT_URL" "$OUT_DIR/$SCT_ARCHIVE" "$SCT_SHA256"

if [[ ! -f "$OUT_DIR/SctPackageX64/X64/SCT.efi" ]]; then
  echo "Extracting $SCT_ARCHIVE"
  rm -rf "$OUT_DIR/SctPackageX64"
  7z x -y -o"$OUT_DIR" "$OUT_DIR/$SCT_ARCHIVE" >/dev/null
fi

if [[ ! -f "$OUT_DIR/SctPackageX64/X64/SCT.efi" ]]; then
  echo "SCT extraction did not produce $OUT_DIR/SctPackageX64/X64/SCT.efi" >&2
  exit 1
fi

cat <<EOF
UEFI SCT smoke assets ready:
  $OUT_DIR/$SHELL_FILE
  $OUT_DIR/SctPackageX64/X64/SCT.efi

Run with:
  ./crabefi test --app uefi-sct-smoke --sct-assets-dir ${OUT_DIR#$ROOT_DIR/} --disable-kvm --timeout 180
EOF
