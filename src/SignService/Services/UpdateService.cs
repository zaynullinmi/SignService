using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SignService.Services;

/// <summary>
/// Автообновление программы через GitHub Releases: проверка последнего релиза,
/// скачивание нового SignService.exe и самозамена (Windows) через командный
/// помощник, который дожидается выхода программы и заменяет exe с резервной копией.
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

        var tempPath = Path.Combine(Path.GetTempPath(), $"SignService-{update.Version}-{Guid.NewGuid():N}.exe");
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
        if (!Path.GetFileName(currentExe).Equals("SignService.exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Автообновление доступно при запуске SignService.exe. Скачайте релиз вручную.");
        if (!File.Exists(downloadedExePath))
            throw new FileNotFoundException("Файл обновления не найден.", downloadedExePath);

        var script = BuildInstallScript(currentExe, downloadedExePath, Environment.ProcessId);

        _ = Process.Start(new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                "WindowsPowerShell", "v1.0", "powershell.exe"),
            Arguments = "-NoProfile -NonInteractive -EncodedCommand "
                + Convert.ToBase64String(Encoding.Unicode.GetBytes(script)),
            CreateNoWindow = true,
            UseShellExecute = false,
        }) ?? throw new InvalidOperationException("Не удалось запустить установщик обновления.");
    }

    // Пути передаются как данные JSON/base64, без интерполяции в команды оболочки.
    // Этот же помощник проверяется на временных файлах интеграционными тестами.
    internal static string BuildInstallScript(string currentExe, string downloadedExePath,
        int processId, bool restart = true)
    {
        var config = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        {
            current = Path.GetFullPath(currentExe),
            downloaded = Path.GetFullPath(downloadedExePath),
            parent = processId,
            restart,
        })));
        return $$"""
            $ErrorActionPreference = 'Stop'
            $config = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{{config}}')) | ConvertFrom-Json
            $stage = $config.current + '.' + [Guid]::NewGuid().ToString('N') + '.new'
            $backup = $config.current + '.' + [Guid]::NewGuid().ToString('N') + '.bak'
            $log = $config.downloaded + '.update.log'
            $replaced = $false
            $parentExited = $config.parent -le 0
            try {
                # Подготавливаем полную копию на том же диске до изменения текущего EXE.
                [IO.File]::Copy($config.downloaded, $stage, $false)
                if (([IO.FileInfo]::new($stage)).Length -ne ([IO.FileInfo]::new($config.downloaded)).Length) {
                    throw 'Incomplete update copy'
                }
                $deadline = [DateTime]::UtcNow.AddSeconds(30)
                if (-not $parentExited) {
                    $parentProcess = Get-Process -Id $config.parent -ErrorAction SilentlyContinue
                    if ($null -eq $parentProcess) { $parentExited = $true }
                    else {
                        while (-not $parentProcess.HasExited -and [DateTime]::UtcNow -lt $deadline) {
                            Start-Sleep -Milliseconds 250
                        }
                        $parentExited = $parentProcess.HasExited
                    }
                }
                if (-not $parentExited) { throw 'Timed out waiting for SignService to exit' }
                # Replace атомарен: при ошибке исходный EXE остаётся; резервная копия сохраняется.
                [IO.File]::Replace($stage, $config.current, $backup)
                $replaced = $true
                if ($config.restart) {
                    [Diagnostics.Process]::Start($config.current) | Out-Null
                }
                [IO.File]::WriteAllText($log, 'Update installed. Backup: ' + $backup)
            }
            catch {
                $failure = $_.Exception.Message
                if ($replaced -and [IO.File]::Exists($backup)) {
                    try {
                        $failedUpdate = $stage + '.failed'
                        [IO.File]::Replace($backup, $config.current, $failedUpdate)
                        [IO.File]::Delete($failedUpdate)
                    }
                    catch { $failure += '; rollback failed: ' + $_.Exception.Message + '; backup: ' + $backup }
                }
                try { [IO.File]::WriteAllText($log, $failure) } catch { }
                if ($config.restart -and $parentExited -and [IO.File]::Exists($config.current)) {
                    try { [Diagnostics.Process]::Start($config.current) | Out-Null } catch { }
                }
                exit 1
            }
            finally {
                if ([IO.File]::Exists($stage)) {
                    try { [IO.File]::Delete($stage) } catch { }
                }
            }
            """;
    }
}
