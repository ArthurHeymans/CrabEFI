# nix build --impure -f experiments/linuxboot/security-tools.nix -o .local/linuxboot/security-tools
let
  lock = builtins.fromJSON (builtins.readFile ../../flake.lock);
  source = builtins.getFlake "github:NixOS/nixpkgs/${lock.nodes.nixpkgs.locked.rev}";
  pkgs = import source { system = "x86_64-linux"; };
in
pkgs.symlinkJoin {
  name = "crabefi-windows-security-experiment-tools";
  paths = with pkgs; [
    (import ./tools.nix) swtpm tpm2-tools openssl sbsigntool efitools
    python3Packages.virt-firmware cdrkit
  ];
  postBuild = ''
    mkdir -p "$out/share/linuxboot"
    ln -s ${pkgs.OVMF.fd}/FV/OVMF_VARS.fd "$out/share/linuxboot/OVMF_VARS.fd"
  '';
}
