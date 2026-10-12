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

    private readonly string _settingsDirectory = SettingsDir;
    private readonly string _settingsPath = SettingsPath;

    public AppSettings() { }

    /// <summary>Изолированное хранилище настроек (например, для интеграционных тестов).</summary>
    public AppSettings(string settingsDirectory)
    {
        _settingsDirectory = Path.GetFullPath(settingsDirectory);
        _settingsPath = Path.Combine(_settingsDirectory, "settings.json");
    }

    /// <summary>Отпечаток сертификата подписи по умолчанию.</summary>
    public string? SignCertThumbprint { get; set; }

    /// <summary>Откреплённая (true) или прикреплённая (false) подпись.</summary>
    public bool DetachedSignature { get; set; } = true;

    /// <summary>Объединять свою подпись с существующим .sig (соподписание).</summary>
    public bool MergeWithExisting { get; set; } = true;

    /// <summary>
    /// Сохранять .bak перед любой перезаписью существующего .sig.
    /// По умолчанию выключено: копия всё равно создаётся, если файл заменяется
    /// без объединения, из него исключаются подписанты или пропадает документ,
    /// вложенный в прикреплённую подпись.
    /// </summary>
    public bool CreateSignatureBackup { get; set; }

    /// <summary>
    /// Все файлы очереди используют режим первого файла
    /// («Создать новую» или «Добавить к существующей»).
    /// </summary>
    public bool ApplyCoSignToAll { get; set; }

    /// <summary>Добавлять штамп времени TSA (CAdES-T) в подпись.</summary>
    public bool UseTimestamp { get; set; }

    /// <summary>Адрес службы штампов времени (RFC 3161).</summary>
    public string TsaUrl { get; set; } = "";

    /// <summary>Ставить визуальный штамп о подписании на PDF.</summary>
    public bool UseStamp { get; set; }

    /// <summary>Включать дату подписания в визуальный штамп.</summary>
    public bool StampWithDate { get; set; } = true;

    /// <summary>
    /// true — подписывать копию со штампом (штамп до подписи);
    /// false — подписывать оригинал, копия со штампом отдельно, без подписи
    /// (безопасно при нескольких подписантах).
    /// </summary>
    public bool StampSignCopy { get; set; }

    /// <summary>Режим страниц штампа (Last/First/All/Custom).</summary>
    public string StampPagesMode { get; set; } = "Last";

    /// <summary>Номера страниц для режима Custom («1,3-5»).</summary>
    public string? StampCustomPages { get; set; }

    /// <summary>Путь к логотипу организации для штампа (PNG/JPEG).</summary>
    public string? StampLogoPath { get; set; }

    /// <summary>Сертификаты, сохранённые на этот компьютер (PFX в папке приложения).</summary>
    public List<SavedCertificateInfo> SavedCertificates { get; set; } = new();

    /// <summary>
    /// Отпечатки сертификатов, установленных этой программой в системное хранилище
    /// Windows, — удалить из хранилища программа разрешает только их.
    /// </summary>
    public List<string> InstalledInStore { get; set; } = new();

    /// <summary>Проверять ли обновления при запуске программы.</summary>
    public bool CheckUpdatesOnStart { get; set; } = true;

    /// <summary>Путь к XML машиночитаемой доверенности (МЧД).</summary>
    public string? PoaXmlPath { get; set; }

    /// <summary>Путь к подписи руководителя (.sig) для МЧД.</summary>
    public string? PoaSigPath { get; set; }

    /// <summary>Дополнительные явно доверенные корни; хранилище ОС не изменяется.</summary>
    public List<string> VerificationTrustedRootPaths { get; set; } = new();

    /// <summary>Разрешение запросов CRL/OCSP при проверке ЭЦП.</summary>
    public bool VerificationAllowNetwork { get; set; }

    /// <summary>
    /// Параметры проверки ЭЦП из настроек: дополнительные доверенные корни и разрешение
    /// сетевых запросов CRL/OCSP. Недоступный или повреждённый файл корня пропускается,
    /// а описание добавляется в <paramref name="problems"/> — проверка не прерывается.
    /// </summary>
    public VerificationOptions CreateVerificationOptions(ICollection<string>? problems = null)
    {
        var roots = new List<byte[]>();
        foreach (var path in VerificationTrustedRootPaths)
        {
            try
            {
                var certificate = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(File.ReadAllBytes(path))
                    ?? throw new InvalidDataException("в файле нет сертификата");
                roots.Add(certificate.GetEncoded());
            }
            catch (Exception e)
            {
                problems?.Add($"Доверенный корень «{path}» пропущен: {e.Message}");
            }
        }

        return new VerificationOptions { TrustedRoots = roots, AllowNetwork = VerificationAllowNetwork };
    }

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
            Directory.CreateDirectory(_settingsDirectory);
            File.WriteAllText(_settingsPath, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch
        {
            // настройки некритичны — не роняем подписание из-за них
        }
    }
}
