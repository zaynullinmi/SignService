using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace SignService.Services;

/// <summary>
/// Объединение нескольких CMS/PKCS#7 подписей одного документа в одну
/// (соподписание): в итоговом SignedData — объединение подписантов (SignerInfos),
/// сертификатов и алгоритмов из всех входных подписей.
/// Работает на уровне ASN.1 без криптопровайдера, поэтому объединяет и
/// ГОСТ-подписи на любой платформе. Повторная подпись того же подписанта
/// (по issuer+serial) заменяет его предыдущую: последняя во входном списке побеждает.
/// </summary>
internal static class CmsMerger
{
    private const string SignedDataOid = "1.2.840.113549.1.7.2";

    private sealed class ParsedSignedData
    {
        public int Version;
        public readonly List<byte[]> DigestAlgorithms = new();
        public byte[] EncapContentInfo = Array.Empty<byte>();
        public bool HasContent;
        public readonly List<byte[]> Certificates = new();
        public readonly List<byte[]> Crls = new();
        public readonly List<(string SidKey, byte[] Der)> Signers = new();
    }

    /// <summary>
    /// Объединяет подписи в одну. Входные .sig могут быть в DER/BER или base64/PEM.
    /// Порядок важен: при совпадении подписанта побеждает более поздняя подпись.
    /// </summary>
    public static byte[] Merge(IReadOnlyList<byte[]> signatures)
    {
        if (signatures.Count == 0)
            throw new ArgumentException("Нет подписей для объединения.", nameof(signatures));

        var parsed = signatures.Select(s => Parse(Normalize(s))).ToList();

        var version = parsed.Max(p => p.Version);
        var digestAlgorithms = DedupeBytes(parsed.SelectMany(p => p.DigestAlgorithms));
        var certificates = DedupeBytes(parsed.SelectMany(p => p.Certificates));
        var crls = DedupeBytes(parsed.SelectMany(p => p.Crls));
        // encapContentInfo: предпочитаем вариант с вложенным документом (прикреплённая
        // подпись), иначе берём первый (для откреплённых он одинаков — без eContent).
        var encap = (parsed.FirstOrDefault(p => p.HasContent) ?? parsed[0]).EncapContentInfo;

        // Подписанты: ключ — SignerIdentifier (issuer+serial); последний побеждает.
        var order = new List<string>();
        var bySid = new Dictionary<string, byte[]>();
        foreach (var (sidKey, der) in parsed.SelectMany(p => p.Signers))
        {
            if (!bySid.ContainsKey(sidKey))
                order.Add(sidKey);
            bySid[sidKey] = der;
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())                                              // ContentInfo
        {
            writer.WriteObjectIdentifier(SignedDataOid);
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))  // [0] EXPLICIT
            {
                using (writer.PushSequence())                                      // SignedData
                {
                    writer.WriteInteger(version);

                    using (writer.PushSetOf())
                    {
                        foreach (var alg in digestAlgorithms)
                            writer.WriteEncodedValue(alg);
                    }

                    writer.WriteEncodedValue(encap);

                    if (certificates.Count > 0)
                    {
                        using (writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0)))
                        {
                            foreach (var cert in certificates)
                                writer.WriteEncodedValue(cert);
                        }
                    }

                    if (crls.Count > 0)
                    {
                        using (writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 1)))
                        {
                            foreach (var crl in crls)
                                writer.WriteEncodedValue(crl);
                        }
                    }

                    using (writer.PushSetOf())
                    {
                        foreach (var sidKey in order)
                            writer.WriteEncodedValue(bySid[sidKey]);
                    }
                }
            }
        }

        return writer.Encode();
    }

    /// <summary>Число подписантов в CMS-подписи (для отображения).</summary>
    public static int CountSigners(byte[] signature) => Parse(Normalize(signature)).Signers.Count;

    private static ParsedSignedData Parse(byte[] cms)
    {
        try
        {
            var result = new ParsedSignedData();

            var reader = new AsnReader(cms, AsnEncodingRules.BER);
            var contentInfo = reader.ReadSequence();
            var oid = contentInfo.ReadObjectIdentifier();
            if (oid != SignedDataOid)
                throw new InvalidOperationException($"это не CMS SignedData (contentType {oid})");

            var explicit0 = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            var signedData = explicit0.ReadSequence();

            result.Version = (int)signedData.ReadInteger();

            var digestAlgorithms = signedData.ReadSetOf();
            while (digestAlgorithms.HasData)
                result.DigestAlgorithms.Add(digestAlgorithms.ReadEncodedValue().ToArray());

            result.EncapContentInfo = signedData.ReadEncodedValue().ToArray();
            var encapReader = new AsnReader(result.EncapContentInfo, AsnEncodingRules.BER).ReadSequence();
            encapReader.ReadObjectIdentifier();
            result.HasContent = encapReader.HasData;

            var certsTag = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true);
            if (signedData.HasData && signedData.PeekTag() == certsTag)
            {
                var certs = signedData.ReadSetOf(certsTag);
                while (certs.HasData)
                    result.Certificates.Add(certs.ReadEncodedValue().ToArray());
            }

            var crlsTag = new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true);
            if (signedData.HasData && signedData.PeekTag() == crlsTag)
            {
                var crls = signedData.ReadSetOf(crlsTag);
                while (crls.HasData)
                    result.Crls.Add(crls.ReadEncodedValue().ToArray());
            }

            var signerInfos = signedData.ReadSetOf();
            while (signerInfos.HasData)
            {
                var der = signerInfos.ReadEncodedValue().ToArray();
                result.Signers.Add((SidKeyOf(der), der));
            }

            return result;
        }
        catch (Exception e) when (e is AsnContentException or InvalidOperationException)
        {
            throw new InvalidOperationException(
                "Не удалось разобрать подпись: файл не является корректной CMS/PKCS#7 подписью. " + e.Message, e);
        }
    }

    // Ключ подписанта — DER-байты SignerIdentifier (IssuerAndSerialNumber либо
    // [0] subjectKeyIdentifier), второй элемент SignerInfo.
    private static string SidKeyOf(byte[] signerInfoDer)
    {
        var signerInfo = new AsnReader(signerInfoDer, AsnEncodingRules.BER).ReadSequence();
        signerInfo.ReadInteger();                                      // version
        return Convert.ToHexString(signerInfo.ReadEncodedValue().Span); // sid
    }

    private static List<byte[]> DedupeBytes(IEnumerable<byte[]> items)
    {
        var seen = new HashSet<string>();
        var result = new List<byte[]>();
        foreach (var item in items)
        {
            if (seen.Add(Convert.ToHexString(item)))
                result.Add(item);
        }

        return result;
    }

    /// <summary>
    /// Подпись может прийти в бинарном DER (начинается с 0x30) либо как base64-текст,
    /// возможно в PEM-обёртке (как в ReportGGE). Приводим к бинарному виду.
    /// </summary>
    public static byte[] Normalize(byte[] data)
    {
        if (data.Length == 0 || data[0] == 0x30)
            return data;

        try
        {
            var text = Encoding.ASCII.GetString(data);
            var builder = new StringBuilder(text.Length);
            foreach (var rawLine in text.Split('\n'))
            {
                var line = rawLine.Trim();
                if (line.Length == 0 || line.StartsWith("-----", StringComparison.Ordinal))
                    continue;
                builder.Append(line);
            }

            return Convert.FromBase64String(Regex.Replace(builder.ToString(), @"\s", ""));
        }
        catch (FormatException)
        {
            return data;
        }
    }
}
