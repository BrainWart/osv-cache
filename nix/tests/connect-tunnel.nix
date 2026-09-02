{ pkgs, self, ... }:

pkgs.testers.runNixOSTest {
  name = "osv-cache-connect-tunnel";

  nodes = {
    server = { config, pkgs, ... }: {
      imports = [ self.nixosModules.default ];

      networking.firewall.allowedTCPPorts = [ 8080 ];

      services.osv-cache = {
        enable = true;
        package = self.packages.${pkgs.system}.default;
        port = 8080;
        certificatePath = "/var/lib/osv-cache/cert.pfx";
        certificatePassword = "testpass";
      };

      systemd.services.osv-cache.preStart = ''
        mkdir -p /var/lib/osv-cache
        if [ ! -f /var/lib/osv-cache/cert.pfx ]; then
          ${pkgs.openssl}/bin/openssl req -x509 -newkey rsa:2048 \
            -keyout /var/lib/osv-cache/key.pem -out /var/lib/osv-cache/cert.pem \
            -days 1 -nodes -subj "/CN=server" \
            -addext "subjectAltName=DNS:server,IP:192.168.1.1"
          ${pkgs.openssl}/bin/openssl pkcs12 -export \
            -out /var/lib/osv-cache/cert.pfx \
            -inkey /var/lib/osv-cache/key.pem \
            -in /var/lib/osv-cache/cert.pem \
            -passout pass:testpass
          chmod 644 /var/lib/osv-cache/*
        fi
      '';
    };

    client = { config, pkgs, ... }: {
      environment.systemPackages = [ pkgs.curl ];
    };
  };

  testScript = ''
    start_all()

    server.wait_for_unit("osv-cache.service")
    server.wait_for_open_port(8080)

    # Copy CA cert from server to client via the shared host directory
    server.succeed("cp /var/lib/osv-cache/cert.pem /tmp/shared/ca.pem")
    client.succeed("cp /tmp/shared/ca.pem /tmp/ca.pem")

    # Run the connect tunnel test
    client.succeed("${pkgs.curl}/bin/curl -k -X GET http://server:8080/health")
    client.succeed("${pkgs.curl}/bin/curl -k -X POST --proxy-insecure --proxy http://server:8080/ http://storage.googleapis.com/health")
  '';
}
