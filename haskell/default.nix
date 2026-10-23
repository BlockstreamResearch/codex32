{ nixpkgs ? import <nixpkgs> {}}: nixpkgs.haskellPackages.callPackage ./codex32.nix {}
