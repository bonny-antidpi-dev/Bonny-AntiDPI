using System.Globalization;

namespace Bonny.Dpi;

internal sealed class DomainPolicy
{
    private readonly HashSet<string> _domains;

    private DomainPolicy(HashSet<string> domains) => _domains = domains;

    public static DomainPolicy Load(string path)
    {
        var domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in File.ReadLines(path))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
                continue;

            var normalized = Normalize(line);
            if (normalized.Length > 0)
                domains.Add(normalized);
        }

        if (domains.Count == 0)
            throw new InvalidDataException("В списке Bonny нет целевых доменов.");

        return new DomainPolicy(domains);
    }

    public static string FindListPath(string baseDirectory)
    {
        for (var directory = new DirectoryInfo(baseDirectory); directory is not null; directory = directory.Parent)
        {
            var projectList = Path.Combine(directory.FullName, "src", "Bonny.Dpi", "domains.txt");
            if (File.Exists(projectList))
                return projectList;
        }

        return Path.Combine(baseDirectory, "domains.txt");
    }

    public bool Includes(string host)
    {
        var normalized = Normalize(host);
        if (normalized.Length == 0)
            return false;

        foreach (var domain in _domains)
        {
            if (normalized.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
                normalized.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static string Normalize(string value)
    {
        value = value.Trim().TrimEnd('.');
        if (value.Length == 0 || value.Contains('*') || value.Contains('/'))
            return string.Empty;

        try
        {
            return new IdnMapping().GetAscii(value).ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            return string.Empty;
        }
    }
}
