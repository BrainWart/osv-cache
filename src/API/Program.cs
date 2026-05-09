using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using API;
using Microsoft.AspNetCore.Server.Kestrel.Https;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel((context, serverOptions) =>
{
    var certConfig = context.Configuration.GetSection("Kestrel:Certificates:Default");
    var certPath = certConfig["Path"]
        ?? throw new InvalidOperationException(
            "Kestrel:Certificates:Default:Path is required. See README.md for configuration.");

    var httpsOptions = new HttpsConnectionAdapterOptions
    {
        ServerCertificate = LoadCertificate(certPath, certConfig["Password"]),
        SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
    };

    serverOptions.Listen(IPAddress.Any, 8080, listenOptions =>
    {
        listenOptions.Use(next =>
        {
            var loggerFactory = listenOptions.ApplicationServices.GetRequiredService<ILoggerFactory>();
            var logger = loggerFactory.CreateLogger<ConnectTunnelMiddleware>();
            var middleware = new ConnectTunnelMiddleware(next, httpsOptions, logger);
            return middleware.OnConnectionAsync;
        });
    });
});

var app = builder.Build();

app.MapGet("/", () => "Hello World!");

app.MapGet("/api/test", () => Results.Ok(new { status = "ok", message = "Test endpoint reached" }));

app.MapGet("/api/echo", (HttpRequest request) => Results.Ok(new
{
    method = request.Method,
    path = request.Path.Value,
    isHttps = request.IsHttps,
    headers = request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString())
}));

app.Run();

static X509Certificate2 LoadCertificate(string path, string? password)
{
    if (!File.Exists(path))
    {
        throw new FileNotFoundException($"Certificate file not found: {path}");
    }

    return X509CertificateLoader.LoadPkcs12FromFile(path, password);
}
