using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

internal static partial class BlockedMediaListUpdater
{
    private const string ApiEndpoint = "https://ru.wikipedia.org/w/api.php";
    private const string BeginMarker = "# BEGIN Bonny managed blocked-media domains";
    private const string EndMarker = "# END Bonny managed blocked-media domains";
    private const int MinimumDomainCount = 10;

    public static async Task<int> UpdateAsync(string domainsPath)
    {
        try
        {
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("BonnyAntiDPI/1.0 (domain-list updater)");
            var url = ApiEndpoint +
                "?action=parse&page=" + Uri.EscapeDataString("Список_заблокированных_в_России_СМИ") +
                "&section=1&prop=text&format=json";
            using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
            response.EnsureSuccessStatusCode();
            await using var stream = await response.Content.ReadAsStreamAsync();
            using var document = await JsonDocument.ParseAsync(stream);

            var html = document.RootElement
                .GetProperty("parse")
                .GetProperty("text")
                .GetProperty("*")
                .GetString();
            if (string.IsNullOrWhiteSpace(html))
                throw new InvalidDataException("Источник не вернул таблицу со списком сайтов.");

            var domains = ExtractSiteDomains(html);
            if (domains.Count < MinimumDomainCount)
                throw new InvalidDataException($"Из таблицы извлечено только {domains.Count} доменов; файл не изменён.");

            var current = File.Exists(domainsPath)
                ? await File.ReadAllTextAsync(domainsPath, Encoding.UTF8)
                : string.Empty;
            var updated = ReplaceManagedSection(current, domains);
            var directory = Path.GetDirectoryName(domainsPath)
                ?? throw new InvalidOperationException("Не удалось определить папку domains.txt.");
            Directory.CreateDirectory(directory);
            var temporaryPath = Path.Combine(directory, "domains.txt." + Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                await File.WriteAllTextAsync(temporaryPath, updated, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
                File.Move(temporaryPath, domainsPath, overwrite: true);
            }
            finally
            {
                if (File.Exists(temporaryPath))
                    File.Delete(temporaryPath);
            }

            Console.WriteLine($"Обновлено доменов СМИ: {domains.Count}.");
            Console.WriteLine("Источник: русская Википедия, раздел «Список заблокированных сайтов средств массовой информации».");
            Console.WriteLine("Это не официальный и не полный реестр РКН; источник может содержать ошибки или устаревшие сведения.");
            Console.WriteLine("Перезапусти Bonny, чтобы он перечитал domains.txt.");
            return 0;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException or UnauthorizedAccessException or InvalidDataException or JsonException or KeyNotFoundException)
        {
            Console.Error.WriteLine("Не удалось обновить список СМИ: " + ex.GetBaseException().Message);
            return 1;
        }
    }

    internal static HashSet<string> ExtractSiteDomains(string html)
    {
        var domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match table in TableRegex().Matches(html))
        {
            var rows = RowRegex().Matches(table.Value);
            if (rows.Count == 0)
                continue;

            var headerCells = CellRegex().Matches(rows[0].Groups[1].Value);
            var siteColumn = -1;
            for (var index = 0; index < headerCells.Count; index++)
            {
                var heading = StripMarkup(headerCells[index].Groups[1].Value);
                if (heading.Equals("Сайт", StringComparison.OrdinalIgnoreCase))
                {
                    siteColumn = index;
                    break;
                }
            }
            if (siteColumn < 0)
                continue;

            foreach (Match row in rows.Cast<Match>().Skip(1))
            {
                var cells = CellRegex().Matches(row.Groups[1].Value);
                if (siteColumn >= cells.Count)
                    continue;

                foreach (Match link in LinkRegex().Matches(cells[siteColumn].Groups[1].Value))
                {
                    var href = WebUtility.HtmlDecode(link.Groups[2].Value);
                    if (!Uri.TryCreate(href, UriKind.Absolute, out var uri) ||
                        uri.Scheme is not ("http" or "https") ||
                        !IsPublicDomain(uri.IdnHost))
                        continue;

                    var host = uri.IdnHost.TrimEnd('.').ToLowerInvariant();
                    if (host.StartsWith("www.", StringComparison.Ordinal))
                        host = host[4..];
                    domains.Add(new IdnMapping().GetAscii(host).ToLowerInvariant());
                }
            }
        }

        return domains;
    }

    internal static string ReplaceManagedSection(string current, IEnumerable<string> domains)
    {
        var lines = current.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n').ToList();
        var start = lines.IndexOf(BeginMarker);
        var end = lines.IndexOf(EndMarker);
        if ((start >= 0) != (end >= 0) || (start >= 0 && end <= start))
            throw new InvalidDataException("Маркеры автоматически обновляемой секции domains.txt повреждены.");

        var managed = new List<string> { BeginMarker };
        managed.AddRange(domains.OrderBy(domain => domain, StringComparer.OrdinalIgnoreCase));
        managed.Add(EndMarker);

        if (start >= 0)
            lines.RemoveRange(start, end - start + 1);
        while (lines.Count > 0 && lines[^1].Length == 0)
            lines.RemoveAt(lines.Count - 1);
        lines.AddRange(managed);
        return string.Join(Environment.NewLine, lines) + Environment.NewLine;
    }

    private static bool IsPublicDomain(string host) =>
        !host.Equals("wikipedia.org", StringComparison.OrdinalIgnoreCase) &&
        !host.EndsWith(".wikipedia.org", StringComparison.OrdinalIgnoreCase) &&
        !host.Equals("wikimedia.org", StringComparison.OrdinalIgnoreCase) &&
        !host.EndsWith(".wikimedia.org", StringComparison.OrdinalIgnoreCase) &&
        !host.Equals("web.archive.org", StringComparison.OrdinalIgnoreCase) &&
        !IPAddress.TryParse(host, out _);

    private static string StripMarkup(string html)
    {
        var withoutTags = TagRegex().Replace(html, " ");
        return string.Join(' ', WebUtility.HtmlDecode(withoutTags)
            .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
    }

    [GeneratedRegex("<table\\b[^>]*>.*?</table\\s*>", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex TableRegex();

    [GeneratedRegex("<tr\\b[^>]*>(.*?)</tr\\s*>", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex RowRegex();

    [GeneratedRegex("<t[hd]\\b[^>]*>(.*?)</t[hd]\\s*>", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex CellRegex();

    [GeneratedRegex("<a\\b[^>]*\\bhref\\s*=\\s*([\"'])(.*?)\\1[^>]*>", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex LinkRegex();

    [GeneratedRegex("<[^>]+>", RegexOptions.Singleline)]
    private static partial Regex TagRegex();
}
