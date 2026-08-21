using System;
using System.Formats.Asn1;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;

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
        string RepresentativeSnils);

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
        var doc = XDocument.Load(xmlPath);
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
        var pred = Find(root, "СвУпПред") is { } up ? Find(up, "СведФизЛ") : null;
        var fio = pred is not null ? Find(pred, "ФИО") : null;

        var repName = string.Join(" ", new[]
        {
            Attr(fio, "Фамилия"), Attr(fio, "Имя"), Attr(fio, "Отчество"),
        }.Where(s => s.Length > 0));

        return new PoaInfo(
            xmlPath,
            sigPath,
            number,
            Date(Attr(svDov, "ДатаВыдДовер")),
            Date(Attr(svDov, "СрокДейст")),
            Attr(org, "НаимОрг"),
            Attr(org, "ИННЮЛ"),
            repName,
            Attr(pred, "ИННФЛ"),
            Attr(pred, "СНИЛС"));
    }

    /// <summary>
    /// Проверяет доверенность: подпись руководителя соответствует XML (по messageDigest,
    /// для ГОСТ — Стрибогом), срок действия не истёк, представитель в МЧД совпадает
    /// с выбранным сертификатом (по ИНН/СНИЛС из subject).
    /// </summary>
    public static CheckResult Validate(PoaInfo poa, X509Certificate2? signerCertificate)
    {
        // 1. Подпись руководителя соответствует файлу МЧД
        try
        {
            var xml = File.ReadAllBytes(poa.XmlPath);
            var sig = File.ReadAllBytes(poa.SigPath);
            switch (CmsMerger.CheckAgainstDocument(sig, xml))
            {
                case CmsMerger.DocMatch.Mismatch:
                    return new CheckResult(CheckState.Error,
                        "Подпись руководителя НЕ соответствует файлу МЧД (подписан другой файл или другая версия).");
                case CmsMerger.DocMatch.Unknown:
                    return new CheckResult(CheckState.Warning,
                        "Не удалось проверить соответствие подписи руководителя файлу МЧД.");
            }
        }
        catch (Exception e)
        {
            return new CheckResult(CheckState.Error, "Не удалось разобрать подпись руководителя: " + e.Message);
        }

        // 2. Срок действия
        if (poa.ValidTo is { } validTo && validTo.Date < DateTime.Today)
            return new CheckResult(CheckState.Error,
                $"Срок действия МЧД истёк {validTo:dd.MM.yyyy}.");

        // 3. Представитель соответствует сертификату подписанта
        if (signerCertificate is not null)
        {
            var certInn = Digits(SubjectValue(signerCertificate, InnFlOid))
                is { Length: > 0 } innFl ? innFl : Digits(SubjectValue(signerCertificate, InnLegacyOid));
            var certSnils = Digits(SubjectValue(signerCertificate, SnilsOid));
            var poaInn = Digits(poa.RepresentativeInn);
            var poaSnils = Digits(poa.RepresentativeSnils);

            var innOk = certInn.Length > 0 && poaInn.Length > 0 && certInn == poaInn;
            var snilsOk = certSnils.Length > 0 && poaSnils.Length > 0 && certSnils == poaSnils;

            if (!innOk && !snilsOk)
            {
                if (certInn.Length == 0 && certSnils.Length == 0)
                    return new CheckResult(CheckState.Warning,
                        "В сертификате нет ИНН/СНИЛС — соответствие представителя МЧД не проверено.");
                return new CheckResult(CheckState.Error,
                    $"Представитель в МЧД ({poa.RepresentativeName}) не совпадает с владельцем сертификата по ИНН/СНИЛС.");
            }
        }

        return new CheckResult(CheckState.Ok, "Доверенность проверена: подпись руководителя "
            + "соответствует МЧД, срок действия не истёк"
            + (signerCertificate is null ? "." : ", представитель совпадает с сертификатом."));
    }

    /// <summary>
    /// Копирует файлы МЧД (XML и .sig) в каталог подписанного документа —
    /// как передаёт доверенность Контур. Существующие файлы не перезаписываются.
    /// </summary>
    public static void CopyNextToDocument(PoaInfo poa, string documentPath)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(documentPath)) ?? ".";
        foreach (var source in new[] { poa.XmlPath, poa.SigPath })
        {
            var target = Path.Combine(directory, Path.GetFileName(source));
            if (!File.Exists(target))
                File.Copy(source, target);
        }
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
