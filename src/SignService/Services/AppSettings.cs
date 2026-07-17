using System;
using System.IO;
using System.Text.Json;

namespace SignService.Services;

/// <summary>
/// Настройки приложения (как AppSettings в ReportGGE): выбранный сертификат
/// запоминается по отпечатку, чтобы следующее подписание шло без повторного выбора.
/// Хранится в %AppData%/SignService/settings.json.
/// </summary>
public class AppSettings
{
    private static readonly string SettingsDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SignService");

    private static readonly string SettingsPath = Path.Combine(SettingsDir, "settings.json");

    /// <summary>Отпечаток сертификата подписи по умолчанию.</summary>
    public string? SignCertThumbprint { get; set; }

    /// <summary>Откреплённая (true) или прикреплённая (false) подпись.</summary>
    public bool DetachedSignature { get; set; } = true;

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(SettingsPath))
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(SettingsPath)) ?? new AppSettings();
        }
        catch
        {
            // повреждённый файл настроек — начинаем с настроек по умолчанию
        }

        return new AppSettings();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(SettingsDir);
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch
        {
            // настройки некритичны — не роняем подписание из-за них
        }
    }
}
