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
      };

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
