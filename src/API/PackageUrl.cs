namespace API;

public static class PackageUrl
{
    public static (string? Ecosystem, string? Name, string? Version) Parse(string purl)
    {
        if (!purl.StartsWith("pkg:", StringComparison.Ordinal))
            return (null, null, null);

        string body = purl["pkg:".Length..];

        int hashIndex = body.IndexOf('#');
        if (hashIndex >= 0)
            body = body[..hashIndex];

        int queryIndex = body.IndexOf('?');
        if (queryIndex >= 0)
            body = body[..queryIndex];

        int typeSlash = body.IndexOf('/');
        if (typeSlash < 0)
            return (null, null, null);

        string type = Uri.UnescapeDataString(body[..typeSlash]);
        string rest = body[(typeSlash + 1)..];

        string? version = null;
        int atIndex = rest.LastIndexOf('@');
        if (atIndex >= 0)
        {
            version = Uri.UnescapeDataString(rest[(atIndex + 1)..]);
            rest = rest[..atIndex];
        }

        string name;
        string? ns = null;
        int nameSlash = rest.LastIndexOf('/');
        if (nameSlash >= 0)
        {
            ns = Uri.UnescapeDataString(rest[..nameSlash]);
            name = Uri.UnescapeDataString(rest[(nameSlash + 1)..]);
        }
        else
        {
            name = Uri.UnescapeDataString(rest);
        }

        return (MapEcosystem(type, ns), name, version);
    }

    // Mirrors OSV.dev's own purl -> ecosystem resolution, which maps to the bare
    // OS family name and ignores qualifiers such as "distro" entirely.
    private static string? MapEcosystem(string type, string? ns) => type.ToLowerInvariant() switch
    {
        "npm" => "npm",
        "pypi" => "PyPI",
        "cargo" or "crates.io" => "crates.io",
        "golang" => "Go",
        "maven" => "Maven",
        "gem" => "RubyGems",
        "nuget" => "NuGet",
        "composer" => "Packagist",
        "hex" => "Hex",
        "pub" => "Pub",
        "deb" when string.Equals(ns, "ubuntu", StringComparison.OrdinalIgnoreCase) => "Ubuntu",
        "deb" when string.Equals(ns, "debian", StringComparison.OrdinalIgnoreCase) => "Debian",
        _ => null,
    };
}
