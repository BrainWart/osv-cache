using System.Text.Json;

using API;

using Microsoft.EntityFrameworkCore;

using static Microsoft.AspNetCore.Http.TypedResults;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<VulnerabilityContext>(b =>
{
    builder.Configuration.GetConnectionString("Default");
    b.UseSqlite("Data Source = ./db.sqlite");
});

builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.ConfigureEndpointDefaults(options =>
    {
        options.UseConnect();
    });
});

WebApplication app = builder.Build();

using (IServiceScope scope = app.Services.CreateScope())
{
    VulnerabilityContext con = scope.ServiceProvider.GetRequiredService<VulnerabilityContext>();
    con.Database.EnsureCreated();

    if (!con.Vulnerabilities.Any())
    {
        string exampleDataDir = Path.Combine("..", "..", "example-data", "osv");
        if (Directory.Exists(exampleDataDir))
        {
            var jsonOptions = new JsonSerializerOptions
            {
                AllowOutOfOrderMetadataProperties = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            };

            foreach (string path in Directory.EnumerateFiles(exampleDataDir, "*.json", SearchOption.AllDirectories))
            {
                try
                {
                    Vulnerability? vuln = JsonSerializer.Deserialize<Vulnerability>(System.IO.File.ReadAllText(path), jsonOptions);
                    if (vuln is not null)
                    {
                        con.Vulnerabilities.Add(vuln);
                        con.SaveChanges();
                    }
                }
                catch (Exception ex) when (ex is JsonException or DbUpdateException)
                {
                    // Some fixtures don't fit this model yet (e.g. Ubuntu USN files whose
                    // "related" field is a string array, not embedded Vulnerability objects,
                    // or packages shared by purl across advisories). Skip and keep going.
                    app.Logger.LogWarning(ex, "Skipping OSV fixture {Path}: {Message}", path, ex.Message);
                }
                finally
                {
                    con.ChangeTracker.Clear();
                }
            }
        }
    }
}

app.MapGet("/v1/vulns", (VulnerabilityContext context)
    => context.Vulnerabilities);
app.MapGet("/v1/vulns/{id}", (VulnerabilityContext context, string id)
        => context.Vulnerabilities.Include(x => x.Affected).FirstOrDefault(x => x.Id == id))
    .RequireHost("api.osv.dev");
app.MapPost("/v1/query", async Task<IResult> (VulnerabilityContext context, OsvQueryRequest request) =>
    {
        if (!OsvQueryEngine.TryResolvePackage(request, out string? name, out string? ecosystem, out string? version))
            return BadRequest();

        List<Vulnerability> vulns = await OsvQueryEngine.QueryAsync(context, name!, ecosystem, version);
        return Ok(new { vulns });
    })
    .RequireHost("api.osv.dev");
app.MapPost("/v1/querybatch", () => StatusCode(501))
    .RequireHost("api.osv.dev");

app.MapGet("/osv-vulnerabilities/ecosystems.txt", () => StatusCode(501))
    .RequireHost("storage.googleapis.com");
app.MapGet("/osv-vulnerabilities/all.zip", () => StatusCode(501))
    .RequireHost("storage.googleapis.com");
app.MapGet("/osv-vulnerabilities/modified_id.csv", () => StatusCode(501))
    .RequireHost("storage.googleapis.com");
app.MapGet("/osv-vulnerabilities/{ecosystem}/all.zip", () => StatusCode(501))
    .RequireHost("storage.googleapis.com");
app.MapGet("/osv-vulnerabilities/{ecosystem}/{vulnId}", () => StatusCode(501))
    .RequireHost("storage.googleapis.com");

app.MapGet("/health", () => StatusCode(200));

app.Run();