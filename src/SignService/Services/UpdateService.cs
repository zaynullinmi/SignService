using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SignService.Services;

/// <summary>
/// Автообновление программы через GitHub Releases: проверка последнего релиза,
/// скачивание нового SignService.exe и самозамена (Windows) через командный
/// скрипт, который дожидается выхода программы, подменяет exe и запускает его.
/// </summary>
public class UpdateService
{
    private const string Owner = "zaynullinmi";
    private const string Repo = "SignService";

    private static readonly HttpClient Http = CreateClient();

    private static HttpClient CreateClient()
    {
        var client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        // GitHub API требует User-Agent.
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("SignService", CurrentVersion));
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        return client;
    }

    /// <summary>Текущая версия программы (из метаданных сборки), например «1.0.0».</summary>
    public static string CurrentVersion
    {
        get
        {
            var version = Assembly.GetExecutingAssembly().GetName().Version ?? new Version(0, 0, 0);
            return $"{version.Major}.{version.Minor}.{version.Build}";
        }
    }

    /// <summary>Сведения о доступном обновлении.</summary>
    public sealed record UpdateInfo(string Version, string ReleasePageUrl, string? ExeDownloadUrl);

    /// <summary>
    /// Проверяет последний релиз на GitHub. Возвращает сведения, если он новее
    /// текущей версии, иначе null.
    /// </summary>
    public async Task<UpdateInfo?> CheckForUpdateAsync(CancellationToken cancellationToken = default)
    {
        var json = await Http.GetStringAsync(
            $"https://api.github.com/repos/{Owner}/{Repo}/releases/latest", cancellationToken);
        return ParseLatestRelease(json, CurrentVersion);
    }

    /// <summary>
    /// Разбирает ответ GitHub /releases/latest; возвращает обновление, только если
    /// версия тега (vX.Y.Z) новее текущей. Выделено для тестируемости.
    /// </summary>
    public static UpdateInfo? ParseLatestRelease(string json, string currentVersion)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var tag = root.GetProperty("tag_name").GetString() ?? "";
        var tagVersion = tag.TrimStart('v', 'V');
        if (!Version.TryParse(tagVersion, out var latest))
            return null;
        if (!Version.TryParse(currentVersion, out var current))
            return null;
        // нормализуем до трёх компонентов
        latest = new Version(latest.Major, Math.Max(latest.Minor, 0), Math.Max(latest.Build, 0));
        current = new Version(current.Major, Math.Max(current.Minor, 0), Math.Max(current.Build, 0));
        if (latest <= current)
            return null;

        var pageUrl = root.TryGetProperty("html_url", out var htmlUrl)
            ? htmlUrl.GetString() ?? ""
            : "";

        string? exeUrl = null;
        if (root.TryGetProperty("assets", out var assets))
        {
            foreach (var asset in assets.EnumerateArray())
            {
                var name = asset.GetProperty("name").GetString() ?? "";
                if (name.Equals("SignService.exe", StringComparison.OrdinalIgnoreCase))
                {
                    exeUrl = asset.GetProperty("browser_download_url").GetString();
                    break;
                }
            }
        }

        return new UpdateInfo(tagVersion, pageUrl, exeUrl);
    }

    /// <summary>Скачивает новый exe во временный файл и возвращает путь к нему.</summary>
    public async Task<string> DownloadAsync(UpdateInfo update, CancellationToken cancellationToken = default)
    {
        if (update.ExeDownloadUrl is null)
            throw new InvalidOperationException("В релизе нет файла SignService.exe.");

        var tempPath = Path.Combine(Path.GetTempPath(), $"SignService-{update.Version}.exe");
        var bytes = await Http.GetByteArrayAsync(update.ExeDownloadUrl, cancellationToken);
        if (bytes.Length < 1024 * 1024)
            throw new InvalidOperationException("Скачанный файл подозрительно мал — обновление прервано.");
        await File.WriteAllBytesAsync(tempPath, bytes, cancellationToken);
        return tempPath;
    }

    /// <summary>
    /// Запускает самозамену (только Windows): скрипт дожидается завершения программы,
    /// заменяет текущий exe скачанным и запускает новую версию. Вызывающий должен
    /// закрыть приложение сразу после вызова.
    /// </summary>
    public void ApplyAndRestart(string downloadedExePath)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException(
                "Автозамена доступна только на Windows. Скачайте новую версию со страницы релиза.");

        var currentExe = Environment.ProcessPath
            ?? throw new InvalidOperationException("Не удалось определить путь к текущему exe.");

        var script = Path.Combine(Path.GetTempPath(), "signservice_update.cmd");
        // Ждём, пока exe освободится (программа закрывается), затем подменяем и запускаем.
        File.WriteAllText(script, $"""
            @echo off
            :wait
            timeout /t 1 /nobreak >nul
            del "{currentExe}" 2>nul
            if exist "{currentExe}" goto wait
            move /y "{downloadedExePath}" "{currentExe}" >nul
            start "" "{currentExe}"
            del "%~f0"
            """);

        Process.Start(new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/c \"{script}\"",
            CreateNoWindow = true,
            UseShellExecute = false,
        });
    }
}
