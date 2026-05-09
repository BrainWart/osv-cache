{ pkgs, self, ... }:

let
  # Python script to test CONNECT tunnel
  connectTestScript = pkgs.writeText "connect-test.py" ''
    import socket
    import ssl
    import json
    import sys

    def test_connect_tunnel(proxy_host, proxy_port, target_host):
        # Connect to proxy
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((proxy_host, proxy_port))

        # Send CONNECT request
        connect_request = f"CONNECT {target_host}:443 HTTP/1.1\r\nHost: {target_host}\r\n\r\n"
        sock.sendall(connect_request.encode())

        # Read response
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(1024)
            if not chunk:
                print("Connection closed before receiving full response")
                sys.exit(1)
            response += chunk

        response_str = response.decode()
        print(f"CONNECT response: {response_str.strip()}")

        if "200" not in response_str:
            print("CONNECT failed")
            sys.exit(1)

        print("CONNECT successful, upgrading to TLS...")

        # Wrap socket with TLS
        context = ssl.create_default_context()
        context.load_verify_locations("/tmp/ca.pem")
        context.check_hostname = False

        ssl_sock = context.wrap_socket(sock, server_hostname=target_host)
        print(f"TLS established: {ssl_sock.version()}")

        # Send HTTP request through tunnel
        http_request = f"GET /api/test HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n"
        ssl_sock.sendall(http_request.encode())

        # Read HTTP response
        response = b""
        while True:
            chunk = ssl_sock.recv(4096)
            if not chunk:
                break
            response += chunk

        response_str = response.decode()
        print(f"HTTP response:\n{response_str}")

        ssl_sock.close()

        if "200" in response_str and "ok" in response_str:
            print("TEST PASSED: Successfully reached endpoint through CONNECT tunnel")
            return True
        else:
            print("TEST FAILED: Unexpected response")
            return False

    def test_echo_endpoint(proxy_host, proxy_port, target_host):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((proxy_host, proxy_port))

        connect_request = f"CONNECT {target_host}:443 HTTP/1.1\r\nHost: {target_host}\r\n\r\n"
        sock.sendall(connect_request.encode())

        response = b""
        while b"\r\n\r\n" not in response:
            response += sock.recv(1024)

        context = ssl.create_default_context()
        context.load_verify_locations("/tmp/ca.pem")
        context.check_hostname = False

        ssl_sock = context.wrap_socket(sock, server_hostname=target_host)

        http_request = f"GET /api/echo HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n"
        ssl_sock.sendall(http_request.encode())

        response = b""
        while True:
            chunk = ssl_sock.recv(4096)
            if not chunk:
                break
            response += chunk

        response_str = response.decode()
        print(f"Echo response:\n{response_str}")

        ssl_sock.close()

        # Check that isHttps is true in the response
        if '"isHttps":true' in response_str or '"isHttps": true' in response_str:
            print("TEST PASSED: Connection correctly identified as HTTPS")
            return True
        else:
            print("TEST FAILED: Connection not identified as HTTPS")
            return False

    if __name__ == "__main__":
        success = True
        success = test_connect_tunnel("server", 8080, "server") and success
        success = test_echo_endpoint("server", 8080, "server") and success
        sys.exit(0 if success else 1)
  '';
in
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
      environment.systemPackages = [ pkgs.python3 pkgs.openssl ];
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
    client.succeed("${pkgs.python3}/bin/python3 ${connectTestScript}")
  '';
}
