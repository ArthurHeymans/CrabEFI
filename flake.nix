{
  description = "CrabEFI - A minimal UEFI implementation as a coreboot payload";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # QEMU for testing
            qemu

            # Disk image tools
            parted
            mtools
            dosfstools

            # coreboot tools for adding payload
            coreboot-utils

            # Compression for firmware
            zstd
          ];

          # Rust is managed by rustup via rust-toolchain.toml files
          # Install rustup separately: https://rustup.rs/
          shellHook = ''
            echo "CrabEFI development environment"
            echo ""
            echo "Rust is managed by rustup via rust-toolchain.toml files."
            echo "If you don't have rustup, install it from https://rustup.rs/"
            echo ""
            echo "Run './crabefi --help' for build commands"
          '';
        };
      }
    );
}
