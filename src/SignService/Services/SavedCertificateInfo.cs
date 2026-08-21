using System;

namespace SignService.Services;

/// <summary>
/// Метаданные сертификата, сохранённого на компьютер в PFX-контейнере.
/// Хранятся в настройках, чтобы показывать сертификат в списке без ввода пароля;
/// сам закрытый ключ лежит в файле <see cref="FileName"/> и защищён паролем.
/// </summary>
public class SavedCertificateInfo
{
    /// <summary>Имя PFX-файла в папке сохранённых сертификатов.</summary>
    public string FileName { get; set; } = "";

    public string Thumbprint { get; set; } = "";

    public string Subject { get; set; } = "";

    public string Issuer { get; set; } = "";

    public DateTime NotBefore { get; set; }

    public DateTime NotAfter { get; set; }

    /// <summary>
    /// Открытая часть сертификата (DER, base64) — для показа в списке и штампа
    /// без ввода пароля. Закрытого ключа здесь нет.
    /// </summary>
    public string CertificateBase64 { get; set; } = "";
}
