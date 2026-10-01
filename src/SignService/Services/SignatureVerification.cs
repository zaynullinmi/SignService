using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SignService.Services;

public enum VerificationState { Valid, Invalid, Unknown, NotChecked, NotPresent }

public sealed record VerificationCheck(VerificationState State, string Message)
{
    public static VerificationCheck Valid(string message) => new(VerificationState.Valid, message);
    public static VerificationCheck Invalid(string message) => new(VerificationState.Invalid, message);
    public static VerificationCheck Unknown(string message) => new(VerificationState.Unknown, message);
    public static VerificationCheck NotChecked(string message) => new(VerificationState.NotChecked, message);
}

public sealed record VerificationOptions
{
    public bool CheckCertificateTrust { get; init; } = true;
    public bool CheckRevocation { get; init; } = true;
    public bool AllowNetwork { get; init; }
    public bool UseSystemTrustStore { get; init; } = true;
    public DateTimeOffset ValidationTime { get; init; } = DateTimeOffset.UtcNow;
    public IReadOnlyList<byte[]> TrustedRoots { get; init; } = Array.Empty<byte[]>();
    public IReadOnlyList<byte[]> ExtraCertificates { get; init; } = Array.Empty<byte[]>();
    public IReadOnlyList<byte[]> Crls { get; init; } = Array.Empty<byte[]>();
    public IReadOnlyList<byte[]> OcspResponses { get; init; } = Array.Empty<byte[]>();

    internal static VerificationOptions CryptographyOnly => new()
    {
        CheckCertificateTrust = false, CheckRevocation = false, UseSystemTrustStore = false,
    };
}

public sealed record SignerVerification(
    int Number, string Name, string Issuer, string SerialNumber, string Thumbprint,
    string DigestAlgorithm, DateTime NotBefore, DateTime NotAfter, DateTimeOffset? SigningTime,
    VerificationCheck Document, VerificationCheck Signature, VerificationCheck CertificateBinding,
    VerificationCheck CertificateTrust, VerificationCheck Revocation, VerificationCheck Timestamp,
    DateTimeOffset? TimestampTime, byte[]? Certificate)
{
    public bool CryptographicallyValid => Signature.State == VerificationState.Valid
        && Document.State == VerificationState.Valid
        && CertificateBinding.State is VerificationState.Valid or VerificationState.NotPresent;
}

public sealed record SignatureVerificationResult(
    bool Attached, VerificationCheck Container, IReadOnlyList<SignerVerification> Signers)
{
    public bool CryptographicallyValid => Container.State == VerificationState.Valid
        && Signers.Count > 0 && Signers.All(s => s.CryptographicallyValid);

    public string ToReport(string signatureName, string? documentName)
    {
        var text = new StringBuilder();
        text.AppendLine("ПРОВЕРКА ЭЛЕКТРОННОЙ ПОДПИСИ");
        text.AppendLine("Подпись: " + signatureName);
        text.AppendLine("Документ: " + (documentName ?? (Attached ? "вложен в контейнер" : "не выбран")));
        text.AppendLine("Контейнер: " + Container.Message);
        text.AppendLine($"Подписантов: {Signers.Count}");
        foreach (var signer in Signers)
        {
            text.AppendLine();
            text.AppendLine($"{signer.Number}. {signer.Name}");
            text.AppendLine("   Издатель: " + signer.Issuer);
            text.AppendLine("   Серийный номер: " + signer.SerialNumber);
            text.AppendLine("   Отпечаток SHA-256: " + signer.Thumbprint);
            text.AppendLine($"   Сертификат: {signer.NotBefore:dd.MM.yyyy} — {signer.NotAfter:dd.MM.yyyy}");
            text.AppendLine("   Алгоритм хеша: " + signer.DigestAlgorithm);
            if (signer.SigningTime is { } time)
                text.AppendLine($"   Указанное подписантом время: {time.ToLocalTime():dd.MM.yyyy HH:mm:ss} (без подтверждения TSA)");
            Line("Документ", signer.Document);
            Line("Подпись", signer.Signature);
            Line("Привязка сертификата", signer.CertificateBinding);
            Line("Цепочка доверия", signer.CertificateTrust);
            Line("Отзыв сертификатов", signer.Revocation);
            Line("Метка времени", signer.Timestamp);
            if (signer.TimestampTime is { } timestamp)
                text.AppendLine($"   Время TSA: {timestamp.ToLocalTime():dd.MM.yyyy HH:mm:ss}");
        }
        text.AppendLine();
        text.AppendLine(CryptographicallyValid
            ? "Криптографическая проверка: все подписи корректны и соответствуют документу."
            : "Криптографическая проверка: есть ошибки или непроверенные подписи.");
        text.AppendLine("Доверие, отзыв и метки времени указаны отдельно. «Не проверено» не означает «действительно».");
        return text.ToString();

        void Line(string label, VerificationCheck check) => text.AppendLine($"   {label}: [{Label(check.State)}] {check.Message}");
    }

    public static string Label(VerificationState state) => state switch
    {
        VerificationState.Valid => "OK", VerificationState.Invalid => "ОШИБКА",
        VerificationState.Unknown => "НЕ ОПРЕДЕЛЕНО", VerificationState.NotPresent => "ОТСУТСТВУЕТ",
        _ => "НЕ ПРОВЕРЕНО",
    };
}
