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
            # Rust
            rustup

            # QEMU and TPM emulator for testing
            qemu
            swtpm

            # Disk image tools
            parted
            mtools
            dosfstools

            # coreboot tools for adding payload
            coreboot-utils

            # RISC-V cross-binutils for ELF-to-PE/COFF conversion
            # (Rust has no riscv64gc-unknown-uefi target)
            pkgsCross.riscv64.buildPackages.binutils

            # Compression/archive tools for firmware and SCT assets
            zstd
            p7zip
          ];

          # Rust is managed by rustup via rust-toolchain.toml files
          shellHook = ''
            echo "CrabEFI development environment"
            echo ""
            echo "Rust is managed by rustup via the rust-toolchain.toml file."
            echo ""
            echo "Run './crabefi --help' for build commands"
          '';
        };
      }
    );
}
