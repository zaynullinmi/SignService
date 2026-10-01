using System;
using System.Formats.Asn1;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using System.Xml;
using System.Collections.Generic;

namespace SignService.Services;

/// <summary>
/// Машиночитаемая доверенность (МЧД, формат EMCHD_1 Минцифры/ФНС): разбор XML,
/// проверка подписи руководителя и соответствия представителя выбранному
/// сертификату. Как в Контуре, доверенность НЕ вкладывается в CMS-подпись —
/// файлы МЧД (XML + .sig руководителя) прикладываются рядом с подписанным
/// документом (это подтверждается разбором подписей Контура: специальных
/// атрибутов МЧД в них нет).
/// </summary>
public static class PowerOfAttorneyService
{
    private const string SnilsOid = "1.2.643.100.3";
    private const string InnFlOid = "1.2.643.3.131.1.1";
    private const string InnLegacyOid = "1.2.643.100.4";

    /// <summary>Сведения о доверенности из XML.</summary>
    public sealed record PoaInfo(
        string XmlPath,
        string SigPath,
        string Number,
        DateTime? IssueDate,
        DateTime? ValidTo,
        string PrincipalOrg,
        string PrincipalInn,
        string RepresentativeName,
        string RepresentativeInn,
        string RepresentativeSnils)
    {
        public IReadOnlyList<Representative> Representatives { get; init; } = Array.Empty<Representative>();
    }

    public sealed record Representative(string Name, string Inn, string Snils);
    internal sealed record PoaPackage(PoaInfo Info, byte[] Xml, byte[] Signature, CheckResult Check);

    public enum CheckState
    {
        Ok,
        Warning,
        Error,
    }

    /// <summary>Итог проверки доверенности.</summary>
    public sealed record CheckResult(CheckState State, string Message);

    /// <summary>Разбирает XML МЧД (EMCHD_1). Пространство имён допускается любое.</summary>
    public static PoaInfo Parse(string xmlPath, string sigPath)
    {
        return ParseBytes(File.ReadAllBytes(xmlPath), xmlPath, sigPath);
    }

    private static PoaInfo ParseBytes(byte[] xml, string xmlPath, string sigPath)
    {
        using var input = new MemoryStream(xml, writable: false);
        using var reader = XmlReader.Create(input, new XmlReaderSettings
            { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 8 * 1024 * 1024 });
        var doc = XDocument.Load(reader);
        var root = doc.Root ?? throw new InvalidOperationException("Пустой XML-файл доверенности.");
        if (root.Name.LocalName != "Доверенность")
            throw new InvalidOperationException(
                $"Это не файл МЧД (корневой элемент «{root.Name.LocalName}», ожидается «Доверенность»).");

        XElement? Find(XElement parent, string localName) =>
            parent.Descendants().FirstOrDefault(e => e.Name.LocalName == localName);

        static string Attr(XElement? e, string name) => e?.Attribute(name)?.Value ?? "";

        static DateTime? Date(string value) =>
            DateTime.TryParseExact(value, "yyyy-MM-dd", CultureInfo.InvariantCulture,
                DateTimeStyles.None, out var d) ? d : null;

        var svDov = Find(root, "СвДов");
        var number = Attr(svDov, "НомДовер");
        if (string.IsNullOrWhiteSpace(number))
            number = Attr(svDov, "ВнНомДовер");

        var org = Find(root, "СвРосОрг");
        // Представитель — в блоке СвУпПред; у руководителя (ЛицоБезДов) похожие поля,
        // поэтому ищем строго внутри СвУпПред.
        var representatives = root.Descendants().Where(e => e.Name.LocalName == "СвУпПред")
            .SelectMany(e => e.Descendants().Where(p => p.Name.LocalName == "СведФизЛ"))
            .Select(p => new Representative(string.Join(" ", new[] { Attr(Find(p, "ФИО"), "Фамилия"),
                Attr(Find(p, "ФИО"), "Имя"), Attr(Find(p, "ФИО"), "Отчество") }.Where(s => s.Length > 0)),
                Attr(p, "ИННФЛ"), Attr(p, "СНИЛС"))).Distinct().ToArray();
        var representative = representatives.FirstOrDefault() ?? new Representative("", "", "");

        return new PoaInfo(
            xmlPath,
            sigPath,
            number,
            Date(Attr(svDov, "ДатаВыдДовер")),
            Date(Attr(svDov, "СрокДейст")),
            Attr(org, "НаимОрг"),
            Attr(org, "ИННЮЛ"),
            representative.Name, representative.Inn, representative.Snils) { Representatives = representatives };
    }

    /// <summary>
    /// Проверяет доверенность: подпись руководителя криптографически соответствует XML,
    /// срок действия не истёк, представитель в МЧД совпадает
    /// с выбранным сертификатом (по ИНН/СНИЛС из subject).
    /// </summary>
    public static CheckResult Validate(PoaInfo poa, X509Certificate2? signerCertificate, VerificationOptions? options = null)
    {
        try
        {
            return Prepare(poa, signerCertificate, options).Check;
        }
        catch (Exception e)
        {
            return new CheckResult(CheckState.Error, "Не удалось разобрать подпись руководителя: " + e.Message);
        }

    }

    internal static PoaPackage Prepare(PoaInfo selected, X509Certificate2? signerCertificate,
        VerificationOptions? options = null)
    {
        // Parse, verify and later copy exactly these bytes, never cached fields or a second read.
        var xml = File.ReadAllBytes(selected.XmlPath);
        var sig = File.ReadAllBytes(selected.SigPath);
        var poa = ParseBytes(xml, selected.XmlPath, selected.SigPath);
        var result = Check();
        return new PoaPackage(poa, xml, sig, result);

        CheckResult Check()
        {
            var verification = SignatureVerifier.Verify(sig, xml, options);
            if (!verification.CryptographicallyValid)
                return new CheckResult(CheckState.Error, "Подпись руководителя не прошла полную криптографическую проверку МЧД. "
                    + verification.Container.Message + " " + string.Join("; ", verification.Signers.Select(s => s.Signature.Message + " " + s.Document.Message)));
            if (string.IsNullOrWhiteSpace(poa.Number) || poa.IssueDate is null || poa.ValidTo is null
                || poa.ValidTo < poa.IssueDate)
                return new CheckResult(CheckState.Error, "В МЧД отсутствуют или некорректны номер и даты действия.");
            if (poa.IssueDate.Value.Date > DateTime.Today)
                return new CheckResult(CheckState.Error, "МЧД ещё не вступила в силу.");
            if (poa.ValidTo is { } validTo && validTo.Date < DateTime.Today)
                return new CheckResult(CheckState.Error,
                    $"Срок действия МЧД истёк {validTo:dd.MM.yyyy}.");

            var warnings = new List<string>();
            // Представитель соответствует сертификату подписанта.
            if (signerCertificate is not null)
            {
                var certInn = Digits(SubjectValue(signerCertificate, InnFlOid))
                    is { Length: > 0 } innFl ? innFl : Digits(SubjectValue(signerCertificate, InnLegacyOid));
                var certSnils = Digits(SubjectValue(signerCertificate, SnilsOid));
                var match = poa.Representatives.FirstOrDefault(r =>
                {
                    var inn = Digits(r.Inn); var snils = Digits(r.Snils);
                    return (certInn.Length == 0 || inn.Length == 0 || certInn == inn)
                        && (certSnils.Length == 0 || snils.Length == 0 || certSnils == snils)
                        && (certInn.Length > 0 && certInn == inn || certSnils.Length > 0 && certSnils == snils);
                });
                if (match is null)
                {
                    if (certInn.Length == 0 && certSnils.Length == 0)
                        warnings.Add("В сертификате нет ИНН/СНИЛС — соответствие представителя МЧД не проверено.");
                    else
                        return new CheckResult(CheckState.Error,
                            $"Представитель в МЧД ({poa.RepresentativeName}) не совпадает с владельцем сертификата по ИНН/СНИЛС.");
                }
                else
                    poa = poa with { RepresentativeName = match.Name, RepresentativeInn = match.Inn, RepresentativeSnils = match.Snils };
            }
            foreach (var signer in verification.Signers)
            {
                if (signer.CertificateTrust.State == VerificationState.Invalid || signer.Revocation.State == VerificationState.Invalid)
                    return new CheckResult(CheckState.Error, signer.CertificateTrust.Message + " " + signer.Revocation.Message);
                if (signer.CertificateTrust.State != VerificationState.Valid || signer.Revocation.State != VerificationState.Valid)
                    warnings.Add("Доверие или отзыв сертификата руководителя не подтверждены.");
                var principalInn = Digits(poa.PrincipalInn);
                var cert = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(signer.Certificate!);
                var innValues = cert.SubjectDN.GetValueList(new Org.BouncyCastle.Asn1.DerObjectIdentifier(InnLegacyOid));
                if (innValues.Count > 0 && principalInn.Length > 0 && innValues.Any(v => Digits(v) != principalInn))
                    return new CheckResult(CheckState.Error, "ИНН организации в сертификате руководителя не совпадает с доверителем МЧД.");
                if (innValues.Count == 0 || principalInn.Length == 0)
                    warnings.Add("Связь сертификата руководителя с организацией-доверителем не подтверждена по ИНН.");
            }
            if (signerCertificate is null) warnings.Add("Сертификат представителя не выбран.");
            const string passed = "Подпись МЧД криптографически корректна, срок действия проверен. ";
            return new CheckResult(warnings.Count > 0 ? CheckState.Warning : CheckState.Ok,
                passed + string.Join(" ", warnings.Distinct()) + " Полномочия и отзыв самой МЧД в реестре проверяются отдельно.");
        }
    }

    /// <summary>
    /// Копирует файлы МЧД (XML и .sig) в каталог подписанного документа —
    /// как передаёт доверенность Контур. Существующие файлы не перезаписываются.
    /// </summary>
    public static void CopyNextToDocument(PoaInfo poa, string documentPath)
    {
        var package = Prepare(poa, null);
        if (package.Check.State == CheckState.Error) throw new InvalidOperationException(package.Check.Message);
        CopyPackage(package, documentPath);
    }

    internal static void CheckCopyTargets(PoaPackage package, string documentPath)
    {
        foreach (var (target, bytes) in CopyTargets(package, documentPath))
            if (File.Exists(target) && !File.ReadAllBytes(target).AsSpan().SequenceEqual(bytes))
                throw new IOException($"Рядом с документом уже есть другой файл МЧД «{Path.GetFileName(target)}». Выберите другой каталог.");
    }

    internal static void CopyPackage(PoaPackage package, string documentPath)
    {
        CheckCopyTargets(package, documentPath);
        var created = new List<string>();
        try
        {
            foreach (var (target, bytes) in CopyTargets(package, documentPath))
                if (!File.Exists(target)) { AtomicFile.Write(target, bytes); created.Add(target); }
            CheckCopyTargets(package, documentPath);
        }
        catch { foreach (var path in created) File.Delete(path); throw; }
    }

    private static IEnumerable<(string Path, byte[] Bytes)> CopyTargets(PoaPackage package, string documentPath)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(documentPath))!;
        var xmlTarget = Path.Combine(directory, Path.GetFileName(package.Info.XmlPath));
        var sigTarget = Path.Combine(directory, Path.GetFileName(package.Info.SigPath));
        if (string.Equals(xmlTarget, sigTarget, StringComparison.OrdinalIgnoreCase)
            || new[] { xmlTarget, sigTarget }.Any(p => string.Equals(p, Path.GetFullPath(documentPath), StringComparison.OrdinalIgnoreCase)
                || string.Equals(p, Path.GetFullPath(documentPath + ".sig"), StringComparison.OrdinalIgnoreCase)))
            throw new IOException("Имена файлов МЧД совпадают с документом или его подписью.");
        yield return (xmlTarget, package.Xml);
        yield return (sigTarget, package.Signature);
    }

    /// <summary>Значение RDN субъекта сертификата по OID (СНИЛС/ИНН и т.п.).</summary>
    private static string SubjectValue(X509Certificate2 certificate, string oid)
    {
        try
        {
            foreach (var rdn in certificate.SubjectName.EnumerateRelativeDistinguishedNames())
            {
                if (rdn.HasMultipleElements)
                    continue;
                if (rdn.GetSingleElementType().Value == oid)
                    return rdn.GetSingleElementValue() ?? "";
            }
        }
        catch (Exception e) when (e is System.Security.Cryptography.CryptographicException or AsnContentException)
        {
        }

        return "";
    }

    private static string Digits(string value) => new(value.Where(char.IsDigit).ToArray());
}
