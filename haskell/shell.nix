{ pkgs ? import <nixpkgs> {} }:

pkgs.haskellPackages.shellFor {
  packages = hpkgs: [
    (hpkgs.callPackage ./codex32.nix { })
  ];

  # development tools we use
  nativeBuildInputs = [
    pkgs.cabal-install
  ];
}
