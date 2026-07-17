using System;
using System.IO;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace SignService.Services;

/// <summary>
/// Подписание документов ЭЦП в формате CMS/PKCS#7 (CAdES-BES).
/// На Windows подпись выполняется через CSP, привязанный к сертификату
/// (для ГОСТ-сертификатов — КриптоПро CSP), поэтому при необходимости
/// будет показан системный диалог ввода PIN-кода контейнера.
/// </summary>
public class DocumentSigner
{
    /// <summary>
    /// Подписывает файл и сохраняет подпись рядом с ним в файле "&lt;имя&gt;.sig".
    /// </summary>
    /// <param name="filePath">Путь к подписываемому файлу.</param>
    /// <param name="certificate">Сертификат с закрытым ключом.</param>
    /// <param name="detached">
    /// true — откреплённая подпись (файл .sig содержит только подпись, как требуют
    /// госпорталы и большинство контрагентов); false — прикреплённая (документ внутри .sig).
    /// </param>
    /// <returns>Путь к созданному файлу подписи.</returns>
    public async Task<string> SignFileAsync(
        string filePath,
        X509Certificate2 certificate,
        bool detached = true,
        CancellationToken cancellationToken = default)
    {
        var data = await File.ReadAllBytesAsync(filePath, cancellationToken);

        var signature = Sign(data, certificate, detached);

        var signaturePath = filePath + ".sig";
        await File.WriteAllBytesAsync(signaturePath, signature, cancellationToken);
        return signaturePath;
    }

    /// <summary>
    /// Формирует CMS/PKCS#7 подпись для массива байтов.
    /// </summary>
    public byte[] Sign(byte[] data, X509Certificate2 certificate, bool detached = true)
    {
        if (data is null || data.Length == 0)
            throw new ArgumentException("Нет данных для подписания: файл пуст.", nameof(data));
        if (!certificate.HasPrivateKey)
            throw new InvalidOperationException(
                $"У сертификата «{CertificateProvider.GetSubjectName(certificate)}» нет закрытого ключа.");

        var contentInfo = new ContentInfo(data);
        var signedCms = new SignedCms(contentInfo, detached);

        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate)
        {
            IncludeOption = X509IncludeOption.ExcludeRoot,
        };

        // Штамп времени подписания (PKCS#9 signing time) — обязательный
        // подписанный атрибут для CAdES-BES.
        signer.SignedAttributes.Add(new Pkcs9SigningTime(DateTime.Now));

        // silent: false — разрешаем CSP показать диалог ввода PIN-кода контейнера.
        signedCms.ComputeSignature(signer, silent: false);

        return signedCms.Encode();
    }

    /// <summary>
    /// Проверяет откреплённую подпись для файла.
    /// </summary>
    public bool VerifyDetached(byte[] data, byte[] signature)
    {
        var signedCms = new SignedCms(new ContentInfo(data), detached: true);
        signedCms.Decode(signature);
        try
        {
            // verifySignatureOnly: не требуем доверия ко всей цепочке,
            // проверяем только криптографическую корректность подписи.
            signedCms.CheckSignature(verifySignatureOnly: true);
            return true;
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return false;
        }
    }
}
