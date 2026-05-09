{ buildDotnetModule
, dotnet-sdk_10
, dotnet-aspnetcore_10
}:

buildDotnetModule {
  pname = "osv-cache";
  version = "0.1.0";

  src = ./..;

  projectFile = "src/API/API.csproj";
  nugetDeps = ./deps.json;

  dotnet-sdk = dotnet-sdk_10;
  dotnet-runtime = dotnet-aspnetcore_10;

  executables = [ "API" ];

  meta = {
    description = "OSV Cache API with HTTP CONNECT tunneling";
    mainProgram = "API";
  };
}
