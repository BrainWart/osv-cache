{ powershell
, writeShellApplication
, fetchFromGitHub
}:
let
  version = "1.2";
  src = fetchFromGitHub {
    owner = "bigdawgsfootball";
    repo = "SBOM-Researcher";
    rev = version;
    hash = "sha256-hlX4tiS+Wumm60x1mmtxgw2WUm0wZbSD9tcRacIo5+E=";
  };
in
writeShellApplication {
  name = "SBOMResearcher";
  runtimeInputs = [ powershell ];
  text = ''
    pwsh -Command "Import-Module '${src}/SBOMResearcher.ps1' ; SBOMResearcher" "$@"
  '';

  derivationArgs = {
    inherit version;
    meta = {
      description = "SBOM-Researcher";
      mainProgram = "SBOMResearcher";
    };
  };
}
