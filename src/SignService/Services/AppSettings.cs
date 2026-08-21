using System;
using System.Collections.Generic;
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

    /// <summary>Объединять свою подпись с существующим .sig (соподписание).</summary>
    public bool MergeWithExisting { get; set; } = true;

    /// <summary>Добавлять штамп времени TSA (CAdES-T) в подпись.</summary>
    public bool UseTimestamp { get; set; }

    /// <summary>Адрес службы штампов времени (RFC 3161).</summary>
    public string TsaUrl { get; set; } = "";

    /// <summary>Ставить визуальный штамп о подписании на PDF.</summary>
    public bool UseStamp { get; set; }

    /// <summary>Включать дату подписания в визуальный штамп.</summary>
    public bool StampWithDate { get; set; } = true;

    /// <summary>Путь к логотипу организации для штампа (PNG/JPEG).</summary>
    public string? StampLogoPath { get; set; }

    /// <summary>Сертификаты, сохранённые на этот компьютер (PFX в папке приложения).</summary>
    public List<SavedCertificateInfo> SavedCertificates { get; set; } = new();

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
