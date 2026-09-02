using System.Text.RegularExpressions;

namespace API;

// Generic dotted-version comparer: splits into numeric/alpha runs and compares
// numerically where both sides are numeric, else ordinally. Accurate for semver-style
// versions; not a substitute for ecosystem-specific comparators (e.g. dpkg).
public static partial class VersionComparer
{
    public static int Compare(string a, string b)
    {
        List<string> partsA = Tokenize(a);
        List<string> partsB = Tokenize(b);

        int length = Math.Max(partsA.Count, partsB.Count);
        for (int i = 0; i < length; i++)
        {
            string partA = i < partsA.Count ? partsA[i] : "";
            string partB = i < partsB.Count ? partsB[i] : "";

            int comparison = long.TryParse(partA, out long numA) && long.TryParse(partB, out long numB)
                ? numA.CompareTo(numB)
                : string.CompareOrdinal(partA, partB);

            if (comparison != 0)
                return comparison;
        }

        return 0;
    }

    private static List<string> Tokenize(string version) => TokenPattern().Matches(version)
        .Select(m => m.Value)
        .ToList();

    [GeneratedRegex(@"\d+|[a-zA-Z]+")]
    private static partial Regex TokenPattern();
}
