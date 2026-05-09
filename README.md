# OSV Cache

A .NET 10 web API that handles HTTP CONNECT tunneling with HTTPS inner connections.

## Prerequisites

- .NET 10 SDK (or use `nix develop` to enter a shell with dependencies)

## Configuration

The application uses Kestrel's standard certificate configuration for TLS on tunneled connections.

### Certificate Configuration

Configure via `appsettings.json`:

```json
{
  "Kestrel": {
    "Certificates": {
      "Default": {
        "Path": "path/to/certificate.pfx",
        "Password": "optional-password"
      }
    }
  }
}
```

Or via environment variables:

```bash
export Kestrel__Certificates__Default__Path=/path/to/certificate.pfx
export Kestrel__Certificates__Default__Password=optional-password
```

### Additional TLS Options

You can configure TLS protocols and client certificates using Kestrel's standard options in code or configuration. See [Kestrel HTTPS configuration](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/servers/kestrel/endpoints?view=aspnetcore-10.0) for all available options.

## Development Setup

### Generate a Development Certificate

Using OpenSSL:

```bash
# Generate private key and certificate
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"

# Convert to PKCS#12 format
openssl pkcs12 -export -out dev-cert.pfx -inkey key.pem -in cert.pem -password pass:devpass

# Clean up intermediate files
rm key.pem cert.pem
```

Using .NET CLI:

```bash
dotnet dev-certs https -ep dev-cert.pfx -p devpass
```

Then configure the application:

```json
{
  "Kestrel": {
    "Certificates": {
      "Default": {
        "Path": "dev-cert.pfx",
        "Password": "devpass"
      }
    }
  }
}
```

## Running

```bash
# Enter Nix development shell (optional, provides .NET SDK)
nix develop

# Run the application
dotnet run --project src/API
```

The server listens on port 8080 and accepts HTTP CONNECT requests. After a successful CONNECT handshake, the inner connection is upgraded to HTTPS.
