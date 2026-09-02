using System.Text.Json;

using Microsoft.EntityFrameworkCore;

namespace API;

public static class OsvSeeder
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        AllowOutOfOrderMetadataProperties = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static void SeedFromDirectory(VulnerabilityContext context, string directory, ILogger logger)
    {
        if (context.Vulnerabilities.Any() || !Directory.Exists(directory))
            return;

        foreach (string path in Directory.EnumerateFiles(directory, "*.json", SearchOption.AllDirectories))
        {
            try
            {
                Vulnerability? vuln = JsonSerializer.Deserialize<Vulnerability>(System.IO.File.ReadAllText(path), JsonOptions);
                if (vuln is null)
                    continue;

                ReconcilePackages(context, vuln);
                context.Vulnerabilities.Add(vuln);
                context.SaveChanges();
            }
            catch (Exception ex) when (ex is JsonException or DbUpdateException)
            {
                // Fixtures that still don't fit this model get skipped rather than aborting the seed.
                logger.LogWarning(ex, "Skipping OSV fixture {Path}: {Message}", path, ex.Message);
            }
            finally
            {
                context.ChangeTracker.Clear();
            }
        }
    }

    // Advisories commonly reference the same package (by purl) as earlier advisories, but each
    // fixture file deserializes its own Package instance. Without this, EF tries to INSERT a
    // second row for a purl that's already persisted and SQLite rejects it as a duplicate key.
    private static void ReconcilePackages(VulnerabilityContext context, Vulnerability vuln)
    {
        if (vuln.Affected is null)
            return;

        var seen = new Dictionary<string, Package>();
        foreach (Affect affect in vuln.Affected)
        {
            if (affect.Package is not { } package)
                continue;

            if (seen.TryGetValue(package.Purl, out Package? dedup))
            {
                affect.Package = dedup;
                continue;
            }

            if (context.Set<Package>().Any(p => p.Purl == package.Purl))
                context.Attach(package).State = EntityState.Unchanged;

            seen[package.Purl] = package;
        }
    }
}
