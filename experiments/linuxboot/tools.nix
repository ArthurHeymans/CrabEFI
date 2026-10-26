# nix build --impure -f experiments/linuxboot/tools.nix -o .local/linuxboot/tools
let
  lock = builtins.fromJSON (builtins.readFile ../../flake.lock);
  nixpkgs = builtins.getFlake "github:NixOS/nixpkgs/${lock.nodes.nixpkgs.locked.rev}";
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  static = pkgs.pkgsStatic;
  musl-cc = pkgs.writeShellScriptBin "musl-cc" ''
    exec ${static.stdenv.cc}/bin/x86_64-unknown-linux-musl-cc "$@"
  '';
in
pkgs.symlinkJoin {
  name = "crabefi-linuxboot-experiment-tools";
  paths = with pkgs; [
    gcc binutils python3 cpio gzip xz coreutils kmod
    parted dosfstools mtools p7zip wimlib coreboot-utils
    musl-cc
  ];
  postBuild = ''
    ln -s ${static.busybox}/bin/busybox "$out/bin/busybox"
    ln -s ${static.kexec-tools}/bin/kexec "$out/bin/kexec"
  '';
}
