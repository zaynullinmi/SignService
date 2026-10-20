using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace SignService.Services;

/// <summary>
/// Визуальный штамп на копии документа по его формату: PDF — <see cref="PdfStamper"/>,
/// Word (.docx, .docm) — <see cref="WordStamper"/>. Остальные форматы подписываются без штампа.
/// </summary>
public static class DocumentStamper
{
    public static bool IsSupported(string filePath) =>
        PdfStamper.IsPdf(filePath) || WordStamper.IsWord(filePath);

    /// <summary>«имя (со штампом).pdf» или «имя (со штампом).docx» рядом с документом.</summary>
    public static string StampedCopyPath(string filePath) =>
        WordStamper.IsWord(filePath) ? WordStamper.StampedCopyPath(filePath) : PdfStamper.StampedCopyPath(filePath);

    /// <summary>
    /// Отказ, если у копии со штампом есть своя подпись (в том числе с другим именем):
    /// новая копия — другой файл, и та подпись перестала бы ему соответствовать.
    /// </summary>
    public static void ThrowIfCopySigned(string filePath)
    {
        var copy = StampedCopyPath(filePath);
        var signature = new[] { ".sig", ".p7s", ".p7m" }
            .Select(extension => copy + extension).FirstOrDefault(File.Exists);
        if (signature is null && File.Exists(copy))
        {
            var digests = new DocumentDigests(File.ReadAllBytes(copy));
            var directory = Path.GetDirectoryName(Path.GetFullPath(copy))!;
            foreach (var candidate in Directory.EnumerateFiles(directory).Where(SignatureDiscovery.IsSignatureFile))
            {
                var report = SignatureVerifier.VerifyWithDigests(File.ReadAllBytes(candidate), digests,
                    VerificationOptions.CryptographyOnly);
                // Не затираем и при неопределённой криптопроверке, если хеш документа совпал.
                if (!report.Signers.Any(s => s.Document.State == VerificationState.Valid
                        && s.Signature.State != VerificationState.Invalid))
                    continue;
                signature = candidate;
                break;
            }
        }
        if (signature is null)
            return;
        var name = Path.GetFileName(copy);
        throw new InvalidOperationException(
            $"Копия «{name}» уже подписана («{Path.GetFileName(signature)}»), новая копия со штампом сделала бы эту подпись " +
            $"недействительной. Чтобы добавить подпись к копии, подпишите сам файл «{name}» без штампа; " +
            "чтобы сделать копию заново, удалите или переименуйте её файл подписи.");
    }

    /// <summary>
    /// Создаёт «имя (со штампом).pdf» или «имя (со штампом).docx» рядом с документом.
    /// Подписанная копия не перезаписывается (см. <see cref="ThrowIfCopySigned"/>).
    /// </summary>
    public static string CreateStampedCopy(
        string filePath,
        IReadOnlyList<PdfStamper.StampSigner> signers,
        PdfStamper.StampOptions options)
    {
        ThrowIfCopySigned(filePath);
        if (WordStamper.IsWord(filePath))
            return WordStamper.CreateStampedCopy(filePath, signers, options);
        if (PdfStamper.IsPdf(filePath))
            return PdfStamper.CreateStampedCopy(filePath, signers, options);
        throw new InvalidOperationException(UnsupportedMessage(filePath));
    }

    /// <summary>Все сертификаты — с одной датой и МЧД из параметров.</summary>
    public static string CreateStampedCopy(
        string filePath,
        IReadOnlyList<X509Certificate2> certificates,
        PdfStamper.StampOptions options,
        DateTime signTime)
        => CreateStampedCopy(filePath, PdfStamper.ToSigners(certificates, options, signTime), options);

    /// <summary>
    /// Подписанты для плашек из файлов подписи документа. Плашка «Документ подписан»
    /// ставится только по подписи, которая криптографически проверяется по этому
    /// документу; остальные (другая версия документа, не удалось проверить) — в Skipped.
    /// Время — из атрибута signingTime подписи. Сертификаты освобождаются в Dispose.
    /// </summary>
    public static StampSigners SignersFromSignatures(IEnumerable<byte[]> signatures, byte[] document)
    {
        var signers = new List<PdfStamper.StampSigner>();
        var valid = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var skipped = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var signature in signatures)
        {
            var report = SignatureVerifier.Verify(signature, document, VerificationOptions.CryptographyOnly);
            foreach (var signer in report.Signers)
            {
                if (signer.CryptographicallyValid && signer.Certificate is { } raw)
                {
                    if (valid.Add(signer.Thumbprint))
                        signers.Add(new PdfStamper.StampSigner(
                            new X509Certificate2(raw), signer.SigningTime?.ToLocalTime().DateTime));
                }
                else
                {
                    var key = signer.Thumbprint.Length > 0 ? signer.Thumbprint : $"{skipped.Count}:{signer.Name}";
                    skipped.TryAdd(key, DisplayName(signer));
                }
            }
        }

        // Подпись, проверенная в одном файле, не считается пропущенной из-за другого.
        return new StampSigners(signers,
            skipped.Where(pair => !valid.Contains(pair.Key)).Select(pair => pair.Value).Distinct().ToList());
    }

    private static string DisplayName(SignerVerification signer)
    {
        if (signer.Certificate is not { } raw)
            return signer.Name;
        try
        {
            using var certificate = new X509Certificate2(raw);
            return CertificateProvider.GetSubjectName(certificate);
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return signer.Name;
        }
    }

    /// <summary>Тот же владелец ключа (сравнение по отпечатку сертификата).</summary>
    public static bool SameCertificate(X509Certificate2 left, X509Certificate2 right) =>
        string.Equals(left.Thumbprint, right.Thumbprint, StringComparison.OrdinalIgnoreCase);

    /// <summary>Подписанты для плашек и имена тех, чьи подписи к документу не подошли.</summary>
    public sealed class StampSigners : IDisposable
    {
        public StampSigners(IReadOnlyList<PdfStamper.StampSigner> signers, IReadOnlyList<string> skipped)
        {
            Signers = signers;
            Skipped = skipped;
        }

        public IReadOnlyList<PdfStamper.StampSigner> Signers { get; }

        public IReadOnlyList<string> Skipped { get; }

        public void Dispose()
        {
            foreach (var signer in Signers)
                signer.Certificate.Dispose();
        }
    }

    /// <summary>
    /// Пояснение для лога: почему штампа нет или почему он стоит не на выбранных
    /// страницах (Word). null — штамп поставлен так, как выбрано.
    /// </summary>
    public static string? Note(string filePath, PdfStamper.StampOptions options) =>
        WordStamper.IsWord(filePath) ? WordStamper.PlacementNote(options)
        : PdfStamper.IsPdf(filePath) ? null
        : UnsupportedMessage(filePath);

    /// <summary>Как назвать формат в сообщении об ошибке штампа.</summary>
    public static string FormatName(string filePath) =>
        WordStamper.IsWord(filePath) ? "документ Word" : "PDF";

    private static string UnsupportedMessage(string filePath)
    {
        var extension = Path.GetExtension(filePath).ToLowerInvariant();
        return extension is ".doc" or ".rtf" or ".odt"
            ? $"штамп не ставится: формат {extension} не поддерживается — сохраните документ как .docx"
            : "штамп не ставится: поддерживаются PDF и документы Word (.docx, .docm)";
    }
}
