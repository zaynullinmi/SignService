using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace SignService.Services;

/// <summary>
/// Подписание документов ЭЦП в формате CMS/PKCS#7 (схема портирована из ReportGGE).
/// На Windows подпись создаётся нативным CryptSignMessage (см. <see cref="NativeSign"/>):
/// .NET SignedCms не умеет ГОСТ, а CryptoAPI отдаёт операцию криптопровайдеру
/// сертификата (для ГОСТ — КриптоПро CSP, с диалогом PIN-кода при необходимости).
/// Вне Windows — запасной путь через SignedCms (RSA/ECDSA).
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

        if (OperatingSystem.IsWindows())
            return SignNative(data, certificate, detached);

        return SignManaged(data, certificate, detached);
    }

    /// <summary>
    /// OID алгоритма хеширования по типу ключа сертификата (как в ReportGGE):
    /// для ГОСТ-ключей — соответствующий ГОСТ Р 34.11, иначе SHA-256.
    /// </summary>
    public static string HashOidFor(X509Certificate2 certificate) =>
        certificate.PublicKey.Oid?.Value switch
        {
            "1.2.643.7.1.1.1.1" => "1.2.643.7.1.1.2.2", // ГОСТ Р 34.10-2012 (256) → 34.11-2012 (256)
            "1.2.643.7.1.1.1.2" => "1.2.643.7.1.1.2.3", // ГОСТ Р 34.10-2012 (512) → 34.11-2012 (512)
            "1.2.643.2.2.19"    => "1.2.643.2.2.9",     // ГОСТ Р 34.10-2001 → 34.11-94
            _ => "2.16.840.1.101.3.4.2.1",              // SHA-256 (RSA/ECDSA)
        };

    /// <summary>Является ли сертификат ГОСТ-сертификатом (ключ ГОСТ Р 34.10).</summary>
    public static bool IsGost(X509Certificate2 certificate) =>
        (certificate.PublicKey.Oid?.Value ?? "").StartsWith("1.2.643.", StringComparison.Ordinal);

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static byte[] SignNative(byte[] data, X509Certificate2 certificate, bool detached)
    {
        // Усиленный формат (CAdES-BES): подписанные атрибуты — время подписания
        // и signing-certificate-v2 (защита от подмены сертификата). content-type
        // и message-digest CryptoAPI добавит сам.
        var attrs = new[]
        {
            new NativeSign.AuthAttribute(
                CadesAttributes.SigningTimeOid,
                CadesAttributes.BuildSigningTime(DateTimeOffset.UtcNow)),
            new NativeSign.AuthAttribute(
                CadesAttributes.SigningCertificateV2Oid,
                CadesAttributes.BuildSigningCertificateV2(certificate)),
        };

        // Вкладываем в подпись всю цепочку (лист + УЦ + корень), как это делает
        // портал в ReportGGE — чтобы подпись проверялась офлайн.
        var embed = BuildChain(certificate);
        try
        {
            return NativeSign.Sign(data, certificate, embed, HashOidFor(certificate), detached, attrs);
        }
        finally
        {
            foreach (var c in embed)
                if (!ReferenceEquals(c, certificate))
                    c.Dispose(); // лист принадлежит вызывающему — не трогаем
        }
    }

    // Запасной путь для Linux/macOS: штатный SignedCms (ГОСТ не поддерживает).
    private static byte[] SignManaged(byte[] data, X509Certificate2 certificate, bool detached)
    {
        if (IsGost(certificate))
            throw new PlatformNotSupportedException(
                "Подписание ГОСТ-сертификатом доступно только на Windows с установленным КриптоПро CSP.");

        var signedCms = new SignedCms(new ContentInfo(data), detached);
        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate)
        {
            IncludeOption = X509IncludeOption.ExcludeRoot,
        };
        // Те же атрибуты CAdES-BES, что и в нативном пути.
        signer.SignedAttributes.Add(new Pkcs9SigningTime(DateTime.Now));
        signer.SignedAttributes.Add(new Pkcs9AttributeObject(
            CadesAttributes.SigningCertificateV2Oid,
            CadesAttributes.BuildSigningCertificateV2(certificate)));
        signedCms.ComputeSignature(signer, silent: false);
        return signedCms.Encode();
    }

    // DER-байты цепочки по отпечатку сертификата. X509Chain.Build — дорогой вызов,
    // а цепочка одного сертификата неизменна; кешируем, чтобы пакетное подписание
    // не строило её заново на каждый файл (как в ReportGGE).
    private static readonly ConcurrentDictionary<string, byte[][]> ChainBlobs = new();

    /// <summary>
    /// Цепочка для вложения в подпись: сам сертификат + найденные сертификаты УЦ.
    /// Если построить цепочку не удалось (нет УЦ в хранилищах) — вернётся только лист.
    /// Все элементы, кроме листа, создаются заново и подлежат Dispose вызывающим.
    /// </summary>
    private static List<X509Certificate2> BuildChain(X509Certificate2 certificate)
    {
        var blobs = ChainBlobs.GetOrAdd(certificate.Thumbprint ?? "", _ => BuildChainBlobs(certificate));
        var list = new List<X509Certificate2> { certificate };
        foreach (var blob in blobs)
        {
            try
            {
                var c = new X509Certificate2(blob);
                if (list.All(x => x.Thumbprint != c.Thumbprint))
                    list.Add(c);
                else
                    c.Dispose();
            }
            catch
            {
                // повреждённый элемент цепочки просто пропускаем
            }
        }

        return list;
    }

    private static byte[][] BuildChainBlobs(X509Certificate2 certificate)
    {
        var blobs = new List<byte[]>();
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            // Нужна сама цепочка, а не вердикт о валидности.
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
            chain.Build(certificate);
            foreach (var element in chain.ChainElements)
                blobs.Add(element.Certificate.RawData);
        }
        catch
        {
            // не построилась — подпишем с одним листовым сертификатом
        }

        return blobs.ToArray();
    }

    /// <summary>
    /// Проверяет откреплённую подпись для файла (только криптографическую
    /// корректность, без проверки доверия цепочки). ГОСТ-подписи вне Windows
    /// проверить нельзя — SignedCms их не разбирает.
    /// </summary>
    public bool VerifyDetached(byte[] data, byte[] signature)
    {
        var signedCms = new SignedCms(new ContentInfo(data), detached: true);
        signedCms.Decode(signature);
        try
        {
            signedCms.CheckSignature(verifySignatureOnly: true);
            return true;
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return false;
        }
    }
}
