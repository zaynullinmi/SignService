using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SignService.Services;

/// <summary>
/// Хранилище сертификатов, сохранённых на локальный компьютер, — чтобы подписывать
/// без подключённого ключа ЭЦП (токена). Сертификат вместе с закрытым ключом
/// экспортируется в PFX-контейнер, защищённый паролем пользователя, в папку
/// %AppData%/SignService/certificates.
///
/// ВАЖНО: хранение ключа в файле снижает безопасность по сравнению с токеном —
/// интерфейс обязан предупреждать пользователя (см. диалог сохранения).
/// Ключи, помеченные при выпуске как неэкспортируемые, сохранить нельзя —
/// это ограничение токена/УЦ, а не программы.
/// </summary>
public class CertificateVault
{
    private static readonly string VaultDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "SignService", "certificates");

    /// <summary>
    /// Сохраняет сертификат с закрытым ключом в защищённый паролем PFX.
    /// </summary>
    public SavedCertificateInfo Save(X509Certificate2 certificate, string password, AppSettings settings)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Пароль не может быть пустым.", nameof(password));
        if (!certificate.HasPrivateKey)
            throw new InvalidOperationException("У выбранного сертификата нет закрытого ключа.");

        byte[] pfx;
        try
        {
            pfx = certificate.Export(X509ContentType.Pfx, password);
        }
        catch (CryptographicException e)
        {
            throw new InvalidOperationException(
                "Не удалось экспортировать закрытый ключ: он помечен как неэкспортируемый "
                + "(это ограничение токена или настройки при выпуске сертификата). "
                + "Сохранить такой сертификат на компьютер нельзя.", e);
        }

        Directory.CreateDirectory(VaultDir);
        var fileName = certificate.Thumbprint + ".pfx";
        File.WriteAllBytes(Path.Combine(VaultDir, fileName), pfx);

        var info = new SavedCertificateInfo
        {
            FileName = fileName,
            Thumbprint = certificate.Thumbprint,
            Subject = CertificateProvider.GetSubjectName(certificate),
            Issuer = CertificateProvider.GetIssuerName(certificate),
            NotBefore = certificate.NotBefore,
            NotAfter = certificate.NotAfter,
            CertificateBase64 = Convert.ToBase64String(certificate.RawData),
        };

        settings.SavedCertificates.RemoveAll(c =>
            string.Equals(c.Thumbprint, info.Thumbprint, StringComparison.OrdinalIgnoreCase));
        settings.SavedCertificates.Add(info);
        settings.Save();
        return info;
    }

    /// <summary>Сохранённые сертификаты, PFX-файлы которых существуют на диске.</summary>
    public IReadOnlyList<SavedCertificateInfo> List(AppSettings settings) =>
        settings.SavedCertificates
            .Where(c => File.Exists(Path.Combine(VaultDir, c.FileName)))
            .ToList();

    /// <summary>Открытая часть сохранённого сертификата (без ключа и без пароля).</summary>
    public static X509Certificate2 PublicPart(SavedCertificateInfo info) =>
        new(Convert.FromBase64String(info.CertificateBase64));

    /// <summary>
    /// Загружает сертификат с закрытым ключом из PFX по паролю — для подписания
    /// без подключённого токена.
    /// </summary>
    public X509Certificate2 Load(SavedCertificateInfo info, string password)
    {
        var path = Path.Combine(VaultDir, info.FileName);
        if (!File.Exists(path))
            throw new InvalidOperationException("Файл сохранённого сертификата не найден: " + path);

        try
        {
            return new X509Certificate2(path, password, X509KeyStorageFlags.Exportable);
        }
        catch (CryptographicException e)
        {
            throw new InvalidOperationException("Неверный пароль сохранённого сертификата.", e);
        }
    }

    /// <summary>Удаляет сохранённый сертификат с компьютера (PFX-файл и запись).</summary>
    public void Delete(SavedCertificateInfo info, AppSettings settings)
    {
        var path = Path.Combine(VaultDir, info.FileName);
        if (File.Exists(path))
        {
            // затираем содержимое перед удалением — в файле лежал закрытый ключ
            try
            {
                var size = new FileInfo(path).Length;
                File.WriteAllBytes(path, new byte[size]);
            }
            catch
            {
                // не удалось затереть — всё равно удаляем
            }

            File.Delete(path);
        }

        settings.SavedCertificates.RemoveAll(c =>
            string.Equals(c.Thumbprint, info.Thumbprint, StringComparison.OrdinalIgnoreCase));
        settings.Save();
    }
}
