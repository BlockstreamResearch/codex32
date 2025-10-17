{ mkDerivation, streams
, lib, tasty, tasty-hunit, tasty-quickcheck
}:
mkDerivation {
  pname = "codex32";
  version = "0.0.0";
  src = lib.sourceFilesBySuffices ./. [".cabal" ".hs"];
  libraryHaskellDepends = [ streams ];
  testHaskellDepends = [
   tasty tasty-hunit tasty-quickcheck
  ];
  license = lib.licenses.mit;
}
