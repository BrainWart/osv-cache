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

    string exampleDataDir = Path.Combine("..", "..", "example-data", "osv");
    OsvSeeder.SeedFromDirectory(con, exampleDataDir, app.Logger);
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