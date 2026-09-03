{ pkgs, self, ... }:

let
  # SBOM-Researcher's Test-PurlFormat only accepts strict x.y.z semver purls, so
  # this uses an npm package rather than example-data's Debian fixture (whose
  # purls carry a "?distro=" qualifier and non-semver version that it rejects).
  # It matches the vulnerable range in example-data/osv/GHSA-hm8q-7f3q-5f36.json
  # (hono, npm, introduced 0 / fixed 4.12.18) so the cached data has a real hit.
  testSbom = pkgs.writeText "hono.spdx.json" (builtins.toJSON {
    SPDXID = "SPDXRef-DOCUMENT";
    spdxVersion = "SPDX-2.3";
    creationInfo = {
      created = "2026-09-02T00:00:00Z";
      creators = [ "Tool: osv-cache-e2e-test" ];
    };
    name = "hono-test-sbom";
    dataLicense = "CC0-1.0";
    documentNamespace = "https://example.com/sbom/hono-test";
    packages = [
      {
        SPDXID = "SPDXRef-Package-hono";
        name = "hono";
        versionInfo = "1.0.0";
        filesAnalyzed = false;
        licenseDeclared = "MIT";
        licenseConcluded = "MIT";
        downloadLocation = "NONE";
        copyrightText = "NOASSERTION";
        checksums = [ ];
        externalRefs = [
          {
            referenceCategory = "PACKAGE-MANAGER";
            referenceType = "purl";
            referenceLocator = "pkg:npm/hono@1.0.0";
          }
        ];
      }
    ];
  });
in
pkgs.testers.runNixOSTest {
  name = "osv-cache-sbom-researcher";

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
          # SAN must cover api.osv.dev: SBOM-Researcher talks TLS to that
          # hostname over the tunnel, and it can't skip certificate checks.
          ${pkgs.openssl}/bin/openssl req -x509 -newkey rsa:2048 \
            -keyout /var/lib/osv-cache/key.pem -out /var/lib/osv-cache/cert.pem \
            -days 1 -nodes -subj "/CN=api.osv.dev" \
            -addext "subjectAltName=DNS:api.osv.dev,DNS:server,IP:192.168.1.1"
          ${pkgs.openssl}/bin/openssl pkcs12 -export \
            -out /var/lib/osv-cache/cert.pfx \
            -inkey /var/lib/osv-cache/key.pem \
            -in /var/lib/osv-cache/cert.pem \
            -passout pass:testpass
          chmod 644 /var/lib/osv-cache/*
        fi

        # Program.cs seeds from "../../example-data/osv" relative to the
        # service's cwd (systemd defaults WorkingDirectory to "/"), which
        # doesn't exist inside the packaged closure. Provide it here so the
        # cache actually has vulnerability data to serve.
        mkdir -p /example-data
        ln -sfn ${self}/example-data/osv /example-data/osv
      '';
    };

    client = { config, pkgs, ... }: {
      environment.systemPackages = [
        pkgs.curl
        self.packages.${pkgs.system}.sbom-researcher
      ];
    };
  };

  testScript = ''
    start_all()

    server.wait_for_unit("osv-cache.service")
    server.wait_for_open_port(8080)

    # Copy the CA cert from server to client via the shared host directory
    server.succeed("cp /var/lib/osv-cache/cert.pem /tmp/shared/ca.pem")
    client.succeed("cp /tmp/shared/ca.pem /tmp/ca.pem")

    client.succeed("cp ${testSbom} /tmp/hono.spdx.json")
    client.succeed("mkdir -p /tmp/out")

    # SBOM-Researcher's vendored script hardcodes calls to
    # https://api.osv.dev/v1/query. Routing them through HTTP_PROXY/HTTPS_PROXY
    # at the osv-cache CONNECT-tunnel makes it transparently answer from the
    # local vulnerability cache instead of the real OSV service.
    client.succeed(
        "HTTP_PROXY=http://server:8080 HTTPS_PROXY=http://server:8080 "
        + "SSL_CERT_FILE=/tmp/ca.pem "
        + "SBOMResearcher -ProjectName hono-test -SBOMPath /tmp/hono.spdx.json "
        + "-wrkDir /tmp/out -minScore 0"
    )

    # example-data/osv/GHSA-hm8q-7f3q-5f36.json covers hono versions before
    # 4.12.18; the SBOM declares 1.0.0, so the cache should flag it.
    client.succeed("grep -r GHSA-hm8q-7f3q-5f36 /tmp/out")
    client.succeed("grep -r 'hono 1.0.0' /tmp/out")
  '';
}
