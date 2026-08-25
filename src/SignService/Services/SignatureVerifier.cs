using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SignService.Services;

/// <summary>
/// Просмотр подписантов и проверка ЭЦП: по каждому подписанту — данные
/// сертификата, время подписания, штамп времени, соответствие документу
/// (по messageDigest; для ГОСТ — Стрибогом, на любой платформе) и
/// криптографическая проверка значения подписи (для ГОСТ — на Windows
/// с установленным криптопровайдером).
/// </summary>
public static class SignatureVerifier
{
    public sealed record SignerReport(
        string Subject,
        string Issuer,
        string Serial,
        DateTime? NotBefore,
        DateTime? NotAfter,
        DateTime? SigningTime,
        bool HasTimestamp,
        string DocMatchText,
        string CryptoText,
        bool Ok);

    public sealed record Report(
        bool Attached,
        IReadOnlyList<SignerReport> Signers,
        string Summary);

    /// <summary>
    /// Проверяет подпись. document — байты документа для откреплённой подписи
    /// (для прикреплённой не нужен: содержимое берётся из контейнера).
    /// </summary>
    public static Report Verify(byte[] signature, byte[]? document)
    {
        var normalized = CmsMerger.Normalize(signature);
        var info = CmsMerger.Inspect(normalized);
        var attached = info.HasContent;

        // Для прикреплённой подписи документ — внутри контейнера.
        var effectiveDocument = attached ? CmsMerger.ExtractContent(normalized) : document;

        // SignedCms для криптопроверки: откреплённой нужен документ.
        SignedCms cms;
        if (attached)
        {
            cms = new SignedCms();
            cms.Decode(normalized);
        }
        else
        {
            cms = new SignedCms(
                new ContentInfo(effectiveDocument ?? Array.Empty<byte>()), detached: true);
            cms.Decode(normalized);
        }

        var docMatches = effectiveDocument is { Length: > 0 }
            ? CmsMerger.CheckSignersAgainstDocument(normalized, effectiveDocument)
            : null;

        var reports = new List<SignerReport>();
        var index = 0;
        foreach (SignerInfo signer in cms.SignerInfos)
        {
            var certificate = signer.Certificate;

            DateTime? signingTime = null;
            foreach (CryptographicAttributeObject attr in signer.SignedAttributes)
            {
                if (attr.Oid.Value == "1.2.840.113549.1.9.5" && attr.Values.Count > 0
                    && attr.Values[0] is Pkcs9SigningTime st)
                    signingTime = st.SigningTime.ToLocalTime();
            }

            var hasTimestamp = signer.UnsignedAttributes.Cast<CryptographicAttributeObject>()
                .Any(a => a.Oid.Value == TimestampClient.TimeStampTokenOid);

            var match = docMatches is not null && index < docMatches.Count
                ? docMatches[index]
                : CmsMerger.DocMatch.Unknown;
            var docText = match switch
            {
                CmsMerger.DocMatch.Match => "✓ соответствует документу",
                CmsMerger.DocMatch.Mismatch => "✗ НЕ соответствует документу (другой файл или версия)",
                _ => effectiveDocument is null
                    ? "— документ не найден, соответствие не проверялось"
                    : "— не удалось проверить соответствие",
            };

            string cryptoText;
            var cryptoOk = false;
            if (match == CmsMerger.DocMatch.Mismatch)
            {
                cryptoText = "✗ подпись сделана под другим содержимым";
            }
            else if (effectiveDocument is null)
            {
                cryptoText = "— без документа криптопроверка невозможна";
            }
            else
            {
                try
                {
                    signer.CheckSignature(verifySignatureOnly: true);
                    cryptoText = "✓ подпись математически верна";
                    cryptoOk = true;
                }
                catch (Exception e) when (e is CryptographicException or PlatformNotSupportedException)
                {
                    var gost = (signer.DigestAlgorithm.Value ?? "").StartsWith("1.2.643.", StringComparison.Ordinal);
                    cryptoText = gost && !HasGostProvider()
                        ? "— криптопроверка ГОСТ доступна на Windows с КриптоПро CSP"
                        : "✗ ПОДПИСЬ НЕ ПРОШЛА КРИПТОПРОВЕРКУ: " + e.Message;
                }
            }

            reports.Add(new SignerReport(
                certificate is null ? "(сертификат не вложен)" : CertificateProvider.GetSubjectName(certificate),
                certificate is null ? "" : CertificateProvider.GetIssuerName(certificate),
                certificate?.SerialNumber ?? "",
                certificate?.NotBefore,
                certificate?.NotAfter,
                signingTime,
                hasTimestamp,
                docText,
                cryptoText,
                match == CmsMerger.DocMatch.Match && (cryptoOk || cryptoText.StartsWith("—"))));
            index++;
        }

        var okCount = reports.Count(r => r.Ok);
        var summary = reports.Count == 0
            ? "В подписи нет подписантов."
            : okCount == reports.Count
                ? $"Все подписанты ({reports.Count}) прошли проверку."
                : $"Прошли проверку: {okCount} из {reports.Count} подписантов.";

        return new Report(attached, reports, summary);
    }

    /// <summary>Текстовый отчёт для окна и лога.</summary>
    public static string Format(Report report, string documentName, string signatureName)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Документ: {documentName}");
        sb.AppendLine($"Подпись: {signatureName} ({(report.Attached ? "прикреплённая — документ внутри" : "откреплённая")})");
        sb.AppendLine($"Подписантов: {report.Signers.Count}");
        sb.AppendLine();

        var i = 1;
        foreach (var s in report.Signers)
        {
            sb.AppendLine($"Подписант {i++}: {s.Subject}");
            if (s.Issuer.Length > 0)
                sb.AppendLine($"  Кем выдан: {s.Issuer}");
            if (s.Serial.Length > 0)
                sb.AppendLine($"  Сертификат № {s.Serial}, действителен {s.NotBefore:dd.MM.yyyy}–{s.NotAfter:dd.MM.yyyy}");
            sb.AppendLine("  Время подписания: "
                + (s.SigningTime is { } t ? t.ToString("dd.MM.yyyy HH:mm:ss") : "не указано")
                + (s.HasTimestamp ? " (есть штамп времени TSA)" : ""));
            sb.AppendLine("  " + s.DocMatchText);
            sb.AppendLine("  " + s.CryptoText);
            sb.AppendLine();
        }

        sb.AppendLine("Итог: " + report.Summary);
        sb.AppendLine();
        sb.AppendLine("Примечание: проверяется соответствие подписи документу и её математическая");
        sb.AppendLine("корректность; доверие к цепочке УЦ и отзыв сертификатов не проверяются.");
        return sb.ToString();
    }

    private static bool HasGostProvider() => OperatingSystem.IsWindows();
}
