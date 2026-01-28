#!/bin/bash
# Build the test EFI application
#
# Usage: ./scripts/build-test-app.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Building test EFI application..."

cd "$PROJECT_DIR/test/hello"
cargo build --release

# Copy the built EFI binary to a convenient location
mkdir -p "$PROJECT_DIR/test"
cp "$PROJECT_DIR/test/hello/target/x86_64-unknown-uefi/release/hello-efi.efi" \
   "$PROJECT_DIR/test/hello.efi"

echo ""
echo "Test application built: $PROJECT_DIR/test/hello.efi"
ls -la "$PROJECT_DIR/test/hello.efi"
