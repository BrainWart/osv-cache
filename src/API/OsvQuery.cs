using Microsoft.EntityFrameworkCore;

namespace API;

public record OsvQueryPackage
{
    public string? Name { get; init; }
    public string? Ecosystem { get; init; }
    public string? Purl { get; init; }
}

public record OsvQueryRequest
{
    public string? Commit { get; init; }
    public string? Version { get; init; }
    public OsvQueryPackage? Package { get; init; }
}

public static class OsvQueryEngine
{
    public static bool TryResolvePackage(
        OsvQueryRequest request, out string? name, out string? ecosystem, out string? version)
    {
        name = request.Package?.Name;
        ecosystem = request.Package?.Ecosystem;
        version = request.Version;

        if (request.Package?.Purl is { } purl)
        {
            (string? purlEcosystem, string? purlName, string? purlVersion) = PackageUrl.Parse(purl);
            name ??= purlName;
            ecosystem ??= purlEcosystem;
            version ??= purlVersion;
        }

        return name is not null;
    }

    public static async Task<List<Vulnerability>> QueryAsync(
        VulnerabilityContext context, string name, string? ecosystem, string? version)
    {
        List<Vulnerability> candidates = await context.Vulnerabilities
            .Include(v => v.Affected!).ThenInclude(a => a.Package)
            .Include(v => v.Affected!).ThenInclude(a => a.Ranges!).ThenInclude(r => ((SemVerAffectRange)r).Events)
            .Include(v => v.Affected!).ThenInclude(a => a.Ranges!).ThenInclude(r => ((EcosystemAffectRange)r).Events)
            .Where(v => v.Affected!.Any(a =>
                a.Package!.Name == name
                && (ecosystem == null
                    || a.Package.Ecosystem == ecosystem
                    || a.Package.Ecosystem.StartsWith(ecosystem + ":"))))
            .ToListAsync();

        if (version is null)
            return candidates;

        return candidates
            .Where(v => v.Affected!.Any(a => AffectMatchesVersion(a, name, ecosystem, version)))
            .ToList();
    }

    private static bool AffectMatchesVersion(Affect affect, string name, string? ecosystem, string version)
    {
        if (affect.Package is null || affect.Package.Name != name)
            return false;

        if (ecosystem is not null
            && affect.Package.Ecosystem != ecosystem
            && !affect.Package.Ecosystem.StartsWith(ecosystem + ":"))
            return false;

        if (affect.Versions is not null && affect.Versions.Contains(version))
            return true;

        if (affect.Ranges is null)
            return false;

        foreach (AffectRange range in affect.Ranges)
        {
            // ECOSYSTEM ranges (e.g. Debian/Ubuntu dpkg versions) aren't evaluated here since
            // correct comparison needs ecosystem-specific rules (epochs, "~" pre-release
            // ordering, etc.); only their explicit Versions list (checked above) is honored.
            if (range is SemVerAffectRange semver && IsVersionInRange(semver.Events, version))
                return true;
        }

        return false;
    }

    private static bool IsVersionInRange(IList<Event> events, string version)
    {
        bool affected = false;
        foreach (Event ev in events)
        {
            if (ev.Introduced is not null)
            {
                if (ev.Introduced == "0" || VersionComparer.Compare(version, ev.Introduced) >= 0)
                    affected = true;
            }
            else if (ev.Fixed is not null && VersionComparer.Compare(version, ev.Fixed) >= 0)
            {
                affected = false;
            }
        }

        return affected;
    }
}
