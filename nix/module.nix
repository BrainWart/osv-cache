{ config, lib, pkgs, ... }:

let
  cfg = config.services.osv-cache;
in
{
  options.services.osv-cache = {
    enable = lib.mkEnableOption "OSV Cache API service";

    package = lib.mkOption {
      type = lib.types.package;
      description = "The OSV Cache API package to use";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 8080;
      description = "Port to listen on";
    };

    certificatePath = lib.mkOption {
      type = lib.types.path;
      description = "Path to the PKCS#12 certificate file";
    };

    certificatePassword = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = "Password for the certificate file";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Whether to open the firewall for the service port";
    };

    databasePath = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/osv-cache/osv-cache.db";
      description = "Filesystem path to the SQLite cache database";
    };

    schedule = lib.mkOption {
      type = lib.types.str;
      default = "0 0 */6 * * *";
      example = "0 0 3 * * *";
      description = ''
        Cron expression controlling when the OSV cache refresh runs.
        Accepts standard 5-field or 6-field (with seconds) syntax.
      '';
    };

    ecosystems = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "npm" "PyPI" "Go" ];
      description = ''
        Ecosystems to download from osv-vulnerabilities.storage.googleapis.com.
        Empty list disables sync.
      '';
    };

    runOnStartup = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Whether to run a sync immediately on service start";
    };

    baseUrl = lib.mkOption {
      type = lib.types.str;
      default = "https://osv-vulnerabilities.storage.googleapis.com";
      description = "Base URL for the OSV ecosystem zip downloads";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.osv-cache = {
      description = "OSV Cache API";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      environment = {
        ASPNETCORE_URLS = "http://0.0.0.0:${toString cfg.port}";
        Kestrel__Certificates__Default__Path = cfg.certificatePath;
        Kestrel__Certificates__Default__Password = cfg.certificatePassword;
        OsvCache__DatabasePath = cfg.databasePath;
        OsvCache__Schedule = cfg.schedule;
        OsvCache__BaseUrl = cfg.baseUrl;
        OsvCache__RunOnStartup = lib.boolToString cfg.runOnStartup;
      } // lib.listToAttrs (lib.imap0
        (i: e: lib.nameValuePair "OsvCache__Ecosystems__${toString i}" e)
        cfg.ecosystems);

      serviceConfig = {
        Type = "exec";
        ExecStart = "${cfg.package}/bin/API";
        Restart = "on-failure";
        RestartSec = 5;
        NoNewPrivileges = true;
        ProtectHome = true;
        PrivateTmp = true;
      };
    };

    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];
  };
}
