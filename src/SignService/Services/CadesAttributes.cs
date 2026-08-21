using System;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SignService.Services;

/// <summary>
/// Подписанные атрибуты CAdES-BES (усиленный формат подписи):
/// время подписания (PKCS#9 signing-time) и ссылка на сертификат подписанта
/// (signing-certificate-v2, RFC 5035) — она защищает подпись от подмены сертификата.
/// </summary>
internal static class CadesAttributes
{
    public const string SigningTimeOid = "1.2.840.113549.1.9.5";
    public const string SigningCertificateV2Oid = "1.2.840.113549.1.9.16.2.47";

    /// <summary>DER-значение атрибута signing-time (UTCTime).</summary>
    public static byte[] BuildSigningTime(DateTimeOffset utcNow)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteUtcTime(utcNow);
        return writer.Encode();
    }

    /// <summary>
    /// DER-значение атрибута signing-certificate-v2 для сертификата подписанта.
    /// certHash считается Стрибогом (ГОСТ Р 34.11-2012) для ГОСТ-2012 ключей —
    /// как делает КриптоПро, — иначе SHA-256 (алгоритм по умолчанию в ESSCertIDv2).
    /// </summary>
    public static byte[] BuildSigningCertificateV2(X509Certificate2 certificate)
    {
        var (hashOid, certHash) = HashCertificate(certificate);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())                      // SigningCertificateV2
        {
            using (writer.PushSequence())                  // certs: SEQUENCE OF ESSCertIDv2
            {
                using (writer.PushSequence())              // ESSCertIDv2
                {
                    // hashAlgorithm DEFAULT sha256 — для SHA-256 по DER опускается.
                    if (hashOid is not null)
                    {
                        using (writer.PushSequence())      // AlgorithmIdentifier
                            writer.WriteObjectIdentifier(hashOid);
                    }

                    writer.WriteOctetString(certHash);     // certHash

                    using (writer.PushSequence())          // IssuerSerial
                    {
                        using (writer.PushSequence())      // GeneralNames
                        {
                            // GeneralName directoryName: [4] EXPLICIT Name
                            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4)))
                                writer.WriteEncodedValue(certificate.IssuerName.RawData);
                        }

                        // Серийный номер — те же байты INTEGER, что в сертификате.
                        writer.WriteInteger(certificate.SerialNumberBytes.Span);
                    }
                }
            }
        }

        return writer.Encode();
    }

    /// <summary>
    /// Хеш DER-представления сертификата для ESSCertIDv2.
    /// Возвращает (OID алгоритма или null для SHA-256 по умолчанию, хеш).
    /// </summary>
    private static (string? HashOid, byte[] Hash) HashCertificate(X509Certificate2 certificate) =>
        certificate.PublicKey.Oid?.Value switch
        {
            "1.2.643.7.1.1.1.1" => ("1.2.643.7.1.1.2.2", Streebog.Hash256(certificate.RawData)),
            "1.2.643.7.1.1.1.2" => ("1.2.643.7.1.1.2.3", Streebog.Hash512(certificate.RawData)),
            _ => (null, SHA256.HashData(certificate.RawData)),
        };
}
