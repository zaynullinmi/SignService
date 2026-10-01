using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using CmsAttribute = Org.BouncyCastle.Asn1.Cms.Attribute;

namespace SignService.Services;

/// <summary>
/// Проверка каждого подписанта и отдельные результаты для документа, подписи,
/// сертификата, доверия, отзыва и TSA. Все алгоритмы, включая ГОСТ, выполняются
/// управляемой библиотекой: криптопровайдер и закрытые ключи для проверки не нужны.
/// </summary>
public static class SignatureVerifier
{
    public static Task<SignatureVerificationResult> VerifyAsync(byte[] signature, byte[]? document = null,
        VerificationOptions? options = null, CancellationToken cancellationToken = default) =>
        Task.Run(() => Verify(signature, document, options, cancellationToken), cancellationToken);

    public static SignatureVerificationResult Verify(byte[] signature, byte[]? document = null,
        VerificationOptions? options = null, CancellationToken cancellationToken = default)
    {
        options ??= new VerificationOptions();
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var normalized = CmsMerger.Normalize(signature);
            var original = new CmsSignedData(normalized);
            var attached = original.SignedContent is not null;
            var embedded = attached ? CmsMerger.ExtractContent(normalized) : null;
            var content = document ?? embedded;
            var cms = content is null ? original : new CmsSignedData(
                new CmsProcessableByteArray(original.SignedContentType, content), normalized);
            var certificates = cms.GetCertificates().EnumerateMatches(null).ToList();
            var crls = cms.GetCrls().EnumerateMatches(null).ToList();
            var results = new List<SignerVerification>();
            foreach (var signer in cms.GetSignerInfos().GetSigners())
            {
                cancellationToken.ThrowIfCancellationRequested();
                var matches = cms.GetCertificates().EnumerateMatches(signer.SignerID).ToList();
                results.Add(VerifySigner(signer, matches, certificates, crls, content,
                    embedded is not null && document is not null && !embedded.AsSpan().SequenceEqual(document),
                    results.Count + 1, options, cancellationToken));
            }
            return new SignatureVerificationResult(attached,
                results.Count == 0 ? VerificationCheck.Invalid("В контейнере нет подписантов.")
                    : VerificationCheck.Valid(attached ? "CMS/PKCS#7, прикреплённая подпись." : "CMS/PKCS#7, откреплённая подпись."),
                results);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception e)
        {
            return new SignatureVerificationResult(false,
                VerificationCheck.Invalid("Файл подписи повреждён или не является CMS/PKCS#7: " + e.Message),
                Array.Empty<SignerVerification>());
        }
    }

    private static SignerVerification VerifySigner(SignerInformation signer, List<X509Certificate> matches,
        List<X509Certificate> certificates, List<X509Crl> crls, byte[]? document, bool attachedMismatch,
        int number, VerificationOptions options, CancellationToken cancellationToken)
    {
        var cert = matches.Count == 1 ? matches[0] : null;
        var documentCheck = document is null
            ? VerificationCheck.NotChecked("Для откреплённой подписи выберите исходный документ.")
            : CheckDocument(signer, document);
        if (attachedMismatch)
            documentCheck = VerificationCheck.Invalid("Вложенный документ отличается от выбранного файла.");
        var binding = cert is null ? VerificationCheck.Unknown("Сертификат подписанта отсутствует или неоднозначен.")
            : CheckCertificateBinding(signer, cert);
        var signatureCheck = VerificationCheck.Unknown("Сертификат подписанта отсутствует или неоднозначен.");
        if (cert is not null && document is not null && documentCheck.State == VerificationState.Unknown)
            signatureCheck = VerificationCheck.Unknown("Проверка подписи невозможна: " + documentCheck.Message);
        else if (cert is not null && document is not null)
        {
            try
            {
                signatureCheck = signer.Verify(cert.GetPublicKey())
                    ? VerificationCheck.Valid("Значение подписи проверено открытым ключом сертификата.")
                    : VerificationCheck.Invalid("Значение подписи неверно: подпись повреждена или подделана.");
            }
            catch (Exception e) when (UnsupportedAlgorithm(e)) { signatureCheck = VerificationCheck.Unknown("Алгоритм не поддерживается: " + e.Message); }
            catch (Exception e) { signatureCheck = VerificationCheck.Invalid("Подпись не прошла проверку: " + e.Message); }
        }
        else if (document is null)
            signatureCheck = VerificationCheck.NotChecked("Нет исходного документа для полной проверки подписи.");

        var timestamp = VerifyTimestamp(signer, options, cancellationToken);
        // signing-time заявлен самим подписантом. Исторический момент допустим только
        // при криптографически корректной метке от доверенной TSA.
        var at = timestamp.Trusted && timestamp.Time is { } stamped ? stamped : options.ValidationTime;
        var certificate = cert is null ? new CertificateValidation(
            VerificationCheck.Unknown("Нет сертификата подписанта."), VerificationCheck.Unknown("Нет сертификата подписанта."))
            : CertificateValidator.Validate(cert, certificates, crls, options with { ValidationTime = at }, cancellationToken);
        return new SignerVerification(number, cert?.SubjectDN.ToString() ?? "Неизвестный подписант",
            cert?.IssuerDN.ToString() ?? "", cert?.SerialNumber.ToString(16).ToUpperInvariant() ?? "",
            cert is null ? "" : Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(cert.GetEncoded())),
            AlgorithmName(signer.DigestAlgorithmID.Algorithm.Id), cert?.NotBefore ?? default, cert?.NotAfter ?? default,
            SigningTime(signer), documentCheck, signatureCheck, binding, certificate.Trust,
            certificate.Revocation, timestamp.Check, timestamp.Time, cert?.GetEncoded());
    }

    private static VerificationCheck CheckDocument(SignerInformation signer, byte[] document)
    {
        try
        {
            var attr = signer.SignedAttributes?[PkcsObjectIdentifiers.Pkcs9AtMessageDigest];
            if (attr is null)
                return VerificationCheck.Valid("Документ проверяется непосредственно значением подписи (без signedAttrs).");
            if (attr.AttrValues.Count != 1)
                return VerificationCheck.Invalid("Некорректный атрибут messageDigest.");
            var digest = Asn1OctetString.GetInstance(attr.AttrValues[0]).GetOctets();
            return DigestUtilities.CalculateDigest(signer.DigestAlgorithmID.Algorithm.Id, document).AsSpan().SequenceEqual(digest)
                ? VerificationCheck.Valid("Хеш соответствует текущему содержимому документа.")
                : VerificationCheck.Invalid("Хеш не совпал: подпись относится к другому файлу или его прежней версии.");
        }
        catch (SecurityUtilityException e) { return VerificationCheck.Unknown("Алгоритм хеша не поддерживается: " + e.Message); }
        catch (Exception e) { return VerificationCheck.Invalid("Не удалось проверить messageDigest: " + e.Message); }
    }

    internal static VerificationCheck CheckCertificateBinding(SignerInformation signer, X509Certificate certificate)
    {
        try
        {
            var oidV2 = new DerObjectIdentifier(CadesAttributes.SigningCertificateV2Oid);
            var oidV1 = new DerObjectIdentifier("1.2.840.113549.1.9.16.2.12");
            var v2 = signer.SignedAttributes?[oidV2];
            var v1 = signer.SignedAttributes?[oidV1];
            if (v1 is null && v2 is null)
                return new VerificationCheck(VerificationState.NotPresent, "Обычная CMS-подпись: signing-certificate отсутствует.");
            if (v2 is not null)
            {
                if (signer.SignedAttributes!.GetAll(oidV2).Count != 1 || v2.AttrValues.Count != 1)
                    return VerificationCheck.Invalid("Неоднозначный signing-certificate-v2.");
                var ids = SigningCertificateV2.GetInstance(v2.AttrValues[0]).GetCerts();
                if (ids.Length == 0 || !DigestUtilities.CalculateDigest(ids[0].HashAlgorithm.Algorithm.Id,
                        certificate.GetEncoded()).AsSpan().SequenceEqual(ids[0].GetCertHash())
                    || !IssuerMatches(ids[0].IssuerSerial, certificate))
                    return VerificationCheck.Invalid("signing-certificate-v2 не соответствует сертификату подписанта.");
            }
            if (v1 is not null)
            {
                if (signer.SignedAttributes!.GetAll(oidV1).Count != 1 || v1.AttrValues.Count != 1)
                    return VerificationCheck.Invalid("Неоднозначный signing-certificate.");
                var ids = SigningCertificate.GetInstance(v1.AttrValues[0]).GetCerts();
                if (ids.Length == 0 || !DigestUtilities.CalculateDigest("SHA-1", certificate.GetEncoded())
                        .AsSpan().SequenceEqual(ids[0].GetCertHash()) || !IssuerMatches(ids[0].IssuerSerial, certificate))
                    return VerificationCheck.Invalid("signing-certificate не соответствует сертификату подписанта.");
            }
            return VerificationCheck.Valid("Хеш и идентификатор сертификата в подписанных атрибутах совпали.");
        }
        catch (SecurityUtilityException e) { return VerificationCheck.Unknown("Алгоритм привязки сертификата не поддерживается: " + e.Message); }
        catch (Exception e) { return VerificationCheck.Invalid("Некорректная привязка сертификата: " + e.Message); }
    }

    private static bool IssuerMatches(IssuerSerial? issuer, X509Certificate certificate) => issuer is null
        || (issuer.Serial.Value.Equals(certificate.SerialNumber) && issuer.Issuer.GetNames().Any(n =>
            n.TagNo == GeneralName.DirectoryName && X509Name.GetInstance(n.Name).Equivalent(certificate.IssuerDN)));

    internal sealed record TimestampVerification(VerificationCheck Check, DateTimeOffset? Time, bool Trusted);

    private static TimestampVerification VerifyTimestamp(SignerInformation signer, VerificationOptions options,
        CancellationToken cancellationToken)
    {
        try
        {
            var oid = new DerObjectIdentifier(TimestampClient.TimeStampTokenOid);
            var attr = signer.UnsignedAttributes?[oid];
            if (attr is null)
                return new TimestampVerification(new VerificationCheck(VerificationState.NotPresent,
                    "Метки TSA нет. signing-time не подтверждает время создания подписи."), null, false);
            if (signer.UnsignedAttributes!.GetAll(oid).Count != 1 || attr.AttrValues.Count != 1)
                return new TimestampVerification(VerificationCheck.Invalid("Неоднозначный атрибут метки времени."), null, false);
            return VerifyTimestampToken(attr.AttrValues[0].GetEncoded(), signer.GetSignature(), options, cancellationToken);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception e) { return new TimestampVerification(VerificationCheck.Invalid("Некорректная метка времени: " + e.Message), null, false); }
    }

    internal static TimestampVerification VerifyTimestampToken(byte[] encodedToken, byte[] signatureValue,
        VerificationOptions options, CancellationToken cancellationToken = default)
    {
        try
        {
            var token = new TimeStampToken(Org.BouncyCastle.Asn1.Cms.ContentInfo.GetInstance(Asn1Object.FromByteArray(encodedToken)));
            var info = token.TimeStampInfo;
            if (!DigestUtilities.CalculateDigest(info.MessageImprintAlgOid, signatureValue).AsSpan()
                    .SequenceEqual(info.GetMessageImprintDigest()))
                return new TimestampVerification(VerificationCheck.Invalid("Метка TSA относится к другому значению подписи."), null, false);
            var matches = token.GetCertificates().EnumerateMatches(token.SignerID).ToList();
            if (matches.Count != 1)
                return new TimestampVerification(VerificationCheck.Invalid("Нет однозначного сертификата TSA."), null, false);
            token.Validate(matches[0]); // подпись, ESSCertID, EKU timeStamping и срок сертификата
            var time = new DateTimeOffset(DateTime.SpecifyKind(info.GenTime, DateTimeKind.Utc));
            if (time > options.ValidationTime.AddMinutes(5))
                return new TimestampVerification(VerificationCheck.Invalid("Метка TSA указывает время в будущем."), time, false);
            var validation = CertificateValidator.Validate(matches[0], token.GetCertificates().EnumerateMatches(null).ToList(),
                token.GetCrls().EnumerateMatches(null).ToList(), options with { ValidationTime = time }, cancellationToken);
            if (!options.CheckCertificateTrust)
                return new TimestampVerification(VerificationCheck.Valid("Подпись и хеш TSA корректны; доверие TSA не проверялось."), time, false);
            var trusted = validation.Trust.State == VerificationState.Valid
                && (!options.CheckRevocation || validation.Revocation.State == VerificationState.Valid);
            return new TimestampVerification(trusted
                ? VerificationCheck.Valid("Подпись, хеш, цепочка доверия и требуемые проверки TSA пройдены.")
                : new VerificationCheck(validation.Trust.State == VerificationState.Invalid || validation.Revocation.State == VerificationState.Invalid
                    ? VerificationState.Invalid : VerificationState.Unknown,
                    "Подпись и хеш TSA корректны. " + validation.Trust.Message + " " + validation.Revocation.Message), time, trusted);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception e) { return new TimestampVerification(VerificationCheck.Invalid("Метка TSA не прошла проверку: " + e.Message), null, false); }
    }

    private static DateTimeOffset? SigningTime(SignerInformation signer)
    {
        try
        {
            var attr = signer.SignedAttributes?[PkcsObjectIdentifiers.Pkcs9AtSigningTime];
            return attr is null ? null : new DateTimeOffset(DateTime.SpecifyKind(
                Org.BouncyCastle.Asn1.Cms.Time.GetInstance(attr.AttrValues[0]).ToDateTime(), DateTimeKind.Utc));
        }
        catch { return null; }
    }

    public static string AlgorithmName(string oid) => oid switch
    {
        "1.2.643.7.1.1.2.2" => "ГОСТ Р 34.11-2012-256",
        "1.2.643.7.1.1.2.3" => "ГОСТ Р 34.11-2012-512",
        "1.2.643.2.2.9" => "ГОСТ Р 34.11-94",
        "2.16.840.1.101.3.4.2.1" => "SHA-256", "2.16.840.1.101.3.4.2.2" => "SHA-384",
        "2.16.840.1.101.3.4.2.3" => "SHA-512", "1.3.14.3.2.26" => "SHA-1", _ => oid,
    };

    private static bool UnsupportedAlgorithm(Exception exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
            if (current is SecurityUtilityException or NotSupportedException) return true;
        return false;
    }
}
