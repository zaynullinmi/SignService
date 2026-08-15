using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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

    /// <summary>Результат объединения с проверкой по документу.</summary>
    public sealed record MergeResult(
        byte[] Signature,
        int SignerCount,
        IReadOnlyList<string> ExcludedSigners,
        IReadOnlyList<string> UnverifiedSigners);

    /// <summary>
    /// Объединяет подписи с проверкой соответствия каждой из них документу:
    /// у подписанта из подписанных атрибутов берётся messageDigest и сравнивается
    /// с хешем документа (ГОСТ Р 34.11-2012 — своей реализацией Стрибога, SHA-1/256/384/512 —
    /// штатно). Подписи, сделанные под другим файлом или прежней версией документа,
    /// ИСКЛЮЧАЮТСЯ из результата (их список — в ExcludedSigners). Подписи, чей алгоритм
    /// хеша проверить нечем, сохраняются и перечисляются в UnverifiedSigners.
    /// </summary>
    public static MergeResult MergeForDocument(IReadOnlyList<byte[]> signatures, byte[] document)
    {
        if (signatures.Count == 0)
            throw new ArgumentException("Нет подписей для объединения.", nameof(signatures));

        var parsed = signatures.Select(s => Parse(Normalize(s))).ToList();

        // Справочник сертификатов всех входов — для имени подписанта в отчёте.
        var certIndex = BuildCertIndex(parsed);
        var hashCache = new Dictionary<string, byte[]?>();
        var excluded = new List<string>();
        var unverified = new List<string>();

        foreach (var p in parsed)
        {
            for (var i = p.Signers.Count - 1; i >= 0; i--)
            {
                var (_, der) = p.Signers[i];
                var check = CheckSignerAgainstDocument(der, document, hashCache);
                if (check == SignerDocMatch.Match)
                    continue;

                var name = SignerDisplayName(der, certIndex);
                if (check == SignerDocMatch.Mismatch)
                {
                    excluded.Add(name);
                    p.Signers.RemoveAt(i);
                }
                else
                {
                    unverified.Add(name);
                }
            }
        }

        if (parsed.All(p => p.Signers.Count == 0))
            throw new InvalidOperationException(
                "Все объединяемые подписи не соответствуют текущему содержимому документа.");

        var merged = BuildMerged(parsed);
        return new MergeResult(
            merged,
            CountSigners(merged),
            excluded.Distinct().ToList(),
            unverified.Distinct().ToList());
    }

    /// <summary>
    /// Объединяет подписи в одну без проверки по документу. Входные .sig могут быть
    /// в DER/BER или base64/PEM. Порядок важен: при совпадении подписанта побеждает
    /// более поздняя подпись.
    /// </summary>
    public static byte[] Merge(IReadOnlyList<byte[]> signatures)
    {
        if (signatures.Count == 0)
            throw new ArgumentException("Нет подписей для объединения.", nameof(signatures));

        return BuildMerged(signatures.Select(s => Parse(Normalize(s))).ToList());
    }

    private static byte[] BuildMerged(List<ParsedSignedData> parsed)
    {

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

    /// <summary>Сводка по контейнеру: прикреплённый ли и имена подписантов.</summary>
    public sealed record ContainerInfo(bool HasContent, IReadOnlyList<string> SignerNames);

    public static ContainerInfo Inspect(byte[] signature)
    {
        var parsed = Parse(Normalize(signature));
        var certIndex = BuildCertIndex(new List<ParsedSignedData> { parsed });
        var names = parsed.Signers.Select(s => SignerDisplayName(s.Der, certIndex)).ToList();
        return new ContainerInfo(parsed.HasContent, names);
    }

    /// <summary>
    /// Извлекает вложенный документ из прикреплённой подписи;
    /// null — если подпись откреплённая (документа внутри нет).
    /// </summary>
    public static byte[]? ExtractContent(byte[] signature)
    {
        var parsed = Parse(Normalize(signature));
        if (!parsed.HasContent)
            return null;

        var encap = new AsnReader(parsed.EncapContentInfo, AsnEncodingRules.BER).ReadSequence();
        encap.ReadObjectIdentifier();                                          // eContentType
        var explicit0 = encap.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        return ReadOctetStringData(explicit0);
    }

    /// <summary>
    /// Преобразует прикреплённую подпись в откреплённую: из контейнера убирается
    /// вложенный документ, подписанты и сертификаты сохраняются.
    /// </summary>
    public static byte[] ConvertToDetached(byte[] signature)
    {
        var parsed = Parse(Normalize(signature));
        parsed.EncapContentInfo = StripContent(parsed.EncapContentInfo);
        parsed.HasContent = false;
        return BuildMerged(new List<ParsedSignedData> { parsed });
    }

    /// <summary>
    /// Разбирает контейнер на отдельные откреплённые подписи — по одной на каждого
    /// подписанта (имя — CN из вложенного сертификата). Сертификаты и CRL сохраняются
    /// в каждой части целиком.
    /// </summary>
    public static IReadOnlyList<(string SignerName, byte[] Signature)> SplitBySigner(byte[] signature)
    {
        var parsed = Parse(Normalize(signature));
        var certIndex = BuildCertIndex(new List<ParsedSignedData> { parsed });
        var strippedEncap = StripContent(parsed.EncapContentInfo);

        var result = new List<(string, byte[])>();
        foreach (var signer in parsed.Signers)
        {
            var single = new ParsedSignedData
            {
                Version = parsed.Version,
                EncapContentInfo = strippedEncap,
                HasContent = false,
            };
            single.DigestAlgorithms.AddRange(parsed.DigestAlgorithms);
            single.Certificates.AddRange(parsed.Certificates);
            single.Crls.AddRange(parsed.Crls);
            single.Signers.Add(signer);

            result.Add((SignerDisplayName(signer.Der, certIndex),
                BuildMerged(new List<ParsedSignedData> { single })));
        }

        return result;
    }

    /// <summary>Значение подписи (поле signature из SignerInfo) первого подписанта.</summary>
    public static byte[] GetSignatureValue(byte[] signature)
    {
        var parsed = Parse(Normalize(signature));
        if (parsed.Signers.Count == 0)
            throw new InvalidOperationException("В подписи нет подписантов.");

        foreach (var (tag, der) in SignerElements(parsed.Signers[0].Der))
        {
            if (tag == new Asn1Tag(UniversalTagNumber.OctetString))
                return new AsnReader(der, AsnEncodingRules.BER).ReadOctetString();
        }

        throw new InvalidOperationException("В SignerInfo не найдено значение подписи.");
    }

    /// <summary>
    /// Добавляет неподписанный (unsigned) атрибут первому подписанту —
    /// например, штамп времени CAdES-T. Значение подписи при этом не меняется,
    /// поэтому подпись остаётся действительной.
    /// </summary>
    public static byte[] AddUnsignedAttribute(byte[] signature, string attrOid, byte[] attrValue)
    {
        var parsed = Parse(Normalize(signature));
        if (parsed.Signers.Count == 0)
            throw new InvalidOperationException("В подписи нет подписантов.");

        var elements = SignerElements(parsed.Signers[0].Der);
        var unsignedTag = new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true);

        // Attribute ::= SEQUENCE { attrType OID, attrValues SET OF ANY }
        var attrWriter = new AsnWriter(AsnEncodingRules.DER);
        using (attrWriter.PushSequence())
        {
            attrWriter.WriteObjectIdentifier(attrOid);
            using (attrWriter.PushSetOf())
                attrWriter.WriteEncodedValue(attrValue);
        }

        var newAttr = attrWriter.Encode();

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            var unsignedWritten = false;
            foreach (var (tag, der) in elements)
            {
                if (tag == unsignedTag)
                {
                    // дополняем существующий unsignedAttrs
                    using (writer.PushSetOf(unsignedTag))
                    {
                        var existing = new AsnReader(der, AsnEncodingRules.BER).ReadSetOf(unsignedTag);
                        while (existing.HasData)
                            writer.WriteEncodedValue(existing.ReadEncodedValue().Span);
                        writer.WriteEncodedValue(newAttr);
                    }

                    unsignedWritten = true;
                }
                else
                {
                    writer.WriteEncodedValue(der);
                }
            }

            if (!unsignedWritten)
            {
                using (writer.PushSetOf(unsignedTag))
                    writer.WriteEncodedValue(newAttr);
            }
        }

        var newSigner = writer.Encode();
        parsed.Signers[0] = (parsed.Signers[0].SidKey, newSigner);
        return BuildMerged(new List<ParsedSignedData> { parsed });
    }

    // Элементы верхнего уровня SignerInfo в исходном порядке (тег + TLV).
    private static List<(Asn1Tag Tag, byte[] Der)> SignerElements(byte[] signerInfoDer)
    {
        var reader = new AsnReader(signerInfoDer, AsnEncodingRules.BER).ReadSequence();
        var elements = new List<(Asn1Tag, byte[])>();
        while (reader.HasData)
            elements.Add((reader.PeekTag(), reader.ReadEncodedValue().ToArray()));
        return elements;
    }

    // EncapContentInfo без eContent: SEQUENCE { eContentType } — для откреплённой подписи.
    private static byte[] StripContent(byte[] encapContentInfo)
    {
        var encap = new AsnReader(encapContentInfo, AsnEncodingRules.BER).ReadSequence();
        var contentType = encap.ReadObjectIdentifier();

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
            writer.WriteObjectIdentifier(contentType);
        return writer.Encode();
    }

    // Содержимое OCTET STRING: примитивного либо составного (BER-чанки, как пишет КриптоПро).
    private static byte[] ReadOctetStringData(AsnReader reader)
    {
        if (reader.TryReadPrimitiveOctetString(out var primitive))
            return primitive.ToArray();

        var constructedTag = new Asn1Tag(TagClass.Universal, (int)UniversalTagNumber.OctetString, isConstructed: true);
        var chunks = reader.ReadSequence(constructedTag);
        using var output = new System.IO.MemoryStream();
        while (chunks.HasData)
        {
            var chunk = ReadOctetStringData(chunks);
            output.Write(chunk, 0, chunk.Length);
        }

        return output.ToArray();
    }

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

    private enum SignerDocMatch
    {
        Match,
        Mismatch,
        Unknown,
    }

    // Сверяет подпись с документом по messageDigest из подписанных атрибутов.
    // Без атрибутов (голый PKCS#7) или с неподдерживаемым алгоритмом хеша — Unknown.
    private static SignerDocMatch CheckSignerAgainstDocument(
        byte[] signerInfoDer, byte[] document, Dictionary<string, byte[]?> hashCache)
    {
        try
        {
            var (digestOid, messageDigest) = InspectSigner(signerInfoDer);
            if (messageDigest is null)
                return SignerDocMatch.Unknown;

            if (!hashCache.TryGetValue(digestOid, out var docHash))
            {
                docHash = HashDocument(digestOid, document);
                hashCache[digestOid] = docHash;
            }

            if (docHash is null)
                return SignerDocMatch.Unknown;

            return docHash.AsSpan().SequenceEqual(messageDigest)
                ? SignerDocMatch.Match
                : SignerDocMatch.Mismatch;
        }
        catch (AsnContentException)
        {
            return SignerDocMatch.Unknown;
        }
    }

    // (OID алгоритма хеша, значение messageDigest из подписанных атрибутов или null).
    private static (string DigestOid, byte[]? MessageDigest) InspectSigner(byte[] signerInfoDer)
    {
        var signerInfo = new AsnReader(signerInfoDer, AsnEncodingRules.BER).ReadSequence();
        signerInfo.ReadInteger();                                    // version
        signerInfo.ReadEncodedValue();                               // sid
        var digestAlgorithm = signerInfo.ReadSequence();             // AlgorithmIdentifier
        var digestOid = digestAlgorithm.ReadObjectIdentifier();

        var signedAttrsTag = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true);
        if (!signerInfo.HasData || signerInfo.PeekTag() != signedAttrsTag)
            return (digestOid, null);

        var attrs = signerInfo.ReadSetOf(signedAttrsTag);
        while (attrs.HasData)
        {
            var attr = attrs.ReadSequence();
            if (attr.ReadObjectIdentifier() == "1.2.840.113549.1.9.4") // messageDigest
            {
                var values = attr.ReadSetOf();
                return (digestOid, values.ReadOctetString());
            }
        }

        return (digestOid, null);
    }

    private static byte[]? HashDocument(string digestOid, byte[] document) => digestOid switch
    {
        "1.2.643.7.1.1.2.2" => Streebog.Hash256(document),   // ГОСТ Р 34.11-2012 (256)
        "1.2.643.7.1.1.2.3" => Streebog.Hash512(document),   // ГОСТ Р 34.11-2012 (512)
        "2.16.840.1.101.3.4.2.1" => SHA256.HashData(document),
        "2.16.840.1.101.3.4.2.2" => SHA384.HashData(document),
        "2.16.840.1.101.3.4.2.3" => SHA512.HashData(document),
        "1.3.14.3.2.26" => SHA1.HashData(document),
        _ => null,                                            // ГОСТ 34.11-94 и прочее — не проверяем
    };

    // «Кому выдан» (CN) сертификата подписанта по его SignerIdentifier, либо номер-заглушка.
    private static string SignerDisplayName(
        byte[] signerInfoDer, IReadOnlyDictionary<string, string> certIndex)
    {
        try
        {
            var sidKey = SidKeyOf(signerInfoDer);
            if (certIndex.TryGetValue(sidKey, out var cn))
                return cn;
        }
        catch (AsnContentException)
        {
        }

        return "неизвестный подписант";
    }

    // Индекс «SignerIdentifier (issuer+serial) → CN» по всем вложенным сертификатам.
    private static IReadOnlyDictionary<string, string> BuildCertIndex(List<ParsedSignedData> parsed)
    {
        var index = new Dictionary<string, string>();
        foreach (var blob in parsed.SelectMany(p => p.Certificates))
        {
            try
            {
                using var cert = new X509Certificate2(blob);
                // Восстанавливаем DER SignerIdentifier: SEQUENCE { issuer Name, serialNumber INTEGER }.
                var writer = new AsnWriter(AsnEncodingRules.DER);
                using (writer.PushSequence())
                {
                    writer.WriteEncodedValue(cert.IssuerName.RawData);
                    writer.WriteInteger(cert.SerialNumberBytes.Span);
                }

                var key = Convert.ToHexString(writer.Encode());
                var cn = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
                index[key] = string.IsNullOrWhiteSpace(cn) ? cert.Subject : cn;
            }
            catch (Exception e) when (e is System.Security.Cryptography.CryptographicException or AsnContentException)
            {
                // непригодный сертификат в контейнере — имя останется заглушкой
            }
        }

        return index;
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
    /// возможно в PEM-обёртке (как в ReportGGE). Приводим к бинарному виду. Затем
    /// перекодируем BER → definite-length (КриптоПро и порталы часто пишут подписи
    /// с неопределённой длиной, которые ASN.1-писатель .NET не принимает) — заодно
    /// отбрасывается «хвост» после подписи.
    /// </summary>
    public static byte[] Normalize(byte[] data)
    {
        var binary = data.Length == 0 || data[0] == 0x30 ? data : DecodeBase64(data);

        if (binary.Length > 0 && binary[0] == 0x30)
        {
            try
            {
                return BerDer.ToDefinite(binary);
            }
            catch (AsnContentException)
            {
                // оставляем как есть — понятная ошибка возникнет при разборе
            }
        }

        return binary;
    }

    private static byte[] DecodeBase64(byte[] data)
    {
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
