{ pkgs ? import <nixpkgs> { }
, stdenv ? pkgs.stdenv
, lib ? pkgs.lib
, ghostscript ? pkgs.ghostscript
, ref ? null
, doPdfGeneration ? true
  # Checks whether the generated output matches the checked-in SSS32.ps.
  # When doing development you may want to shut this off to obtain the
  # output file that you need to check in.
, doOutputDiff ? true
}:

let
  src =
    if isNull ref
    then lib.sourceFilesBySuffices ./. [ ".ps" ".inc" ]
    else
      fetchGit {
        url = ./.;
        inherit ref;
      };
  shortId = lib.optionalString (! isNull ref) ("-" + builtins.substring 0 8 src.rev);

  setup = rec {
    # Will be broken into multiple sub-files in a later PR.
    fullSetup = {
      content = builtins.readFile "${src}/include/setup.ps.inc";
      dependencies = [ ];
    };
  };
  # Dependencies that every page has
  standardDependencies = [ setup.fullSetup ];

  allPages = {
    title = {
      sourceHeader = "Title Page";
      content = builtins.readFile "${src}/include/title.ps.inc";
      dependencies = [ ];
    };
    license = {
      sourceHeader = "License Information";
      drawPageContent = true;
      content = builtins.readFile "${src}/include/license.ps.inc";
      dependencies = [ ];
    };
    reference = {
      sourceHeader = "Reference Sheet";
      drawPageContent = true;
      content = builtins.readFile "${src}/include/reference.ps.inc";
      dependencies = [ ];
    };
    principalTables = {
      sourceHeader = "Arithmetic Tables";
      content = builtins.readFile "${src}/include/principal-tables.ps.inc";
      dependencies = [ ];
    };

    additionBottom = {
      content = "{xor} (Addition) code dup perm drawBottomWheelPage\n";
      dependencies = [ ];
    };
    additionTop = {
      content = "showTopWheelPage\n";
      dependencies = [ ];
    };
    recovery = {
      content = builtins.readFile "${src}/include/volvelle-recovery.ps.inc";
      dependencies = [ ];
    };
    fusionInner = {
      content = builtins.readFile "${src}/include/volvelle-fusion-1.ps.inc";
      dependencies = [ ];
    };
    fusionOuter = {
      content = builtins.readFile "${src}/include/volvelle-fusion-2.ps.inc";
      dependencies = [ ];
    };

    generationInstructions = {
      content = builtins.readFile "${src}/include/page7.ps.inc";
      dependencies = [ ];
    };

    checksumTable1 = {
      content = builtins.readFile "${src}/include/checksum-table-1.ps.inc";
      isLandscape = true;
      dependencies = [ ];
    };
    checksumTable2 = {
      content = builtins.readFile "${src}/include/checksum-table-2.ps.inc";
      isLandscape = true;
      dependencies = [ ];
    };
    checksumWorksheet = {
      content = builtins.readFile "${src}/include/checksum-worksheet.ps.inc";
      isLandscape = true;
      dependencies = [ ];
    };

    shareTable = a: b: c: d: {
      content = "${toString a} ${toString b} ${toString c} ${toString d} showShareTablePage\n";
      dependencies = [ ];
    };
  };

  fullBooklet = {
    name = "SSS32.ps";
    pages = with allPages; [
      title
      license
      reference
      principalTables
      additionBottom
      additionTop
      generationInstructions
      (shareTable 29 24 13 25)
      (shareTable 9 8 23 18)
      (shareTable 22 31 27 19)
      (shareTable 1 0 3 16)
      (shareTable 11 28 12 14)
      (shareTable 6 4 2 15)
      (shareTable 10 17 21 20)
      (shareTable 26 30 7 5)
      recovery
      fusionInner
      fusionOuter
      checksumTable1
      checksumTable2
      checksumWorksheet
    ];
  };

  dependencyContentRecur = content: builtins.concatMap
    (item: (dependencyContentRecur item.dependencies) ++ [ item.content ])
    content;
  dependencyContent = pages: lib.lists.unique (
    (map (dep: dep.content) standardDependencies) ++
    (builtins.concatMap (page: dependencyContentRecur page.dependencies) pages)
  );

  renderBooklet = booklet:
    let
      addPage = content: pageData: {
        content = content.content + lib.optionalString (pageData ? sourceHeader) ''
          %****************************************************************
          %*
          %* ${pageData.sourceHeader}
          %*
          %****************************************************************
        '' + ''
          %%Page: ${toString content.nextPgIdx} ${toString content.nextPgIdx}
          ${lib.optionalString (pageData ? isLandscape) "%%PageOrientation: Landscape\n"}%%BeginPageSetup
          /pgsave save def
          %%EndPageSetup
        '' + (
          if pageData ? drawPageContent
          then
            if pageData ? isLandscape
            then "landscapePage begin ${toString content.nextFooterIdx} drawPageContent\n"
            else "portraitPage begin ${toString content.nextFooterIdx} drawPageContent\n"
          else
            if pageData ? isLandscape
            then "90 rotate\n"
            else ""
        ) + ''
          ${pageData.content}
          ${lib.optionalString (pageData ? drawPageContent) "end\n"}pgsave restore
          showpage
        '';
        nextFooterIdx = content.nextFooterIdx + (if pageData ? drawPageContent then 1 else 0);
        nextPgIdx = content.nextPgIdx + 1;
      };
      initialContent = {
        content = ''
          %!PS-Adobe-3.0
          %%Orientation: Portrait
          %%Pages: ${toString (builtins.length booklet.pages)}
          %%EndComments
          %%BeginSetup
          ${toString (dependencyContent (booklet.pages))}%%EndSetup

          %************************************************************************
          %************************************************************************
          %*
          %* Section Three: Page Rendering
          %*
          %************************************************************************
          %************************************************************************

        '';
        nextPgIdx = 1;
        nextFooterIdx = 1;
      };
      finalContent = builtins.foldl' addPage initialContent booklet.pages;
    in
    pkgs.writeTextFile {
      name = booklet.name;
      text = finalContent.content + ''
        %%EOF
      '';
    };
in
stdenv.mkDerivation {
  name = "codex32${shortId}";

  nativeBuildInputs = if doPdfGeneration then [ ghostscript ] else [ ];

  phases = [ "buildPhase" ];
  buildPhase = ''
    set -e

    mkdir "$out"
    cd "$out"
    ln -s ${renderBooklet fullBooklet} SSS32.ps

    ${lib.optionalString doOutputDiff "diff -C 5 ${src}/SSS32.ps SSS32.ps"}
    sed -i 's/(revision \(.*\))/(revision \1${shortId})/' ./SSS32.ps
    ${lib.optionalString doPdfGeneration "ps2pdf -dPDFSETTINGS=/prepress SSS32.ps"}
  '';
}

