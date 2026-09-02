using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using API;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<VulnerabilityContext>(b =>
{
    builder.Configuration.GetConnectionString("Default");
    b.UseSqlite("Data Source = ./db.sqlite");
});

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

    serverOptions.ConfigureEndpointDefaults(options =>
    {
        options.UseConnect();
    });
});

var app = builder.Build();

using (IServiceScope scope = app.Services.CreateScope())
{
    VulnerabilityContext con = scope.ServiceProvider.GetRequiredService<VulnerabilityContext>();
    con.Database.EnsureCreated();
}

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
