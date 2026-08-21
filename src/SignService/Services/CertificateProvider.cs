using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace SignService.Services;

/// <summary>
/// Доступ к сертификатам ЭЦП из хранилища текущего пользователя.
/// На Windows с установленным КриптоПро CSP сюда попадают в том числе
/// сертификаты ГОСТ Р 34.10-2012, привязанные к контейнерам закрытых ключей.
/// </summary>
public class CertificateProvider
{
    /// <summary>
    /// Возвращает сертификаты с закрытым ключом, пригодные для подписания.
    /// </summary>
    /// <param name="includeExpired">Включать ли просроченные сертификаты.</param>
    public IReadOnlyList<X509Certificate2> GetSigningCertificates(bool includeExpired = false)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);

        var certificates = store.Certificates
            .Cast<X509Certificate2>()
            .Where(c => c.HasPrivateKey)
            .Where(c => includeExpired || (c.NotBefore <= DateTime.Now && c.NotAfter >= DateTime.Now))
            .OrderByDescending(c => c.NotAfter)
            .ToList();

        return certificates;
    }

    /// <summary>
    /// Человекочитаемое имя владельца сертификата (CN из Subject).
    /// </summary>
    public static string GetSubjectName(X509Certificate2 certificate)
    {
        var cn = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        return string.IsNullOrWhiteSpace(cn) ? certificate.Subject : cn;
    }

    /// <summary>
    /// Человекочитаемое имя удостоверяющего центра (CN из Issuer).
    /// </summary>
    public static string GetIssuerName(X509Certificate2 certificate)
    {
        var cn = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: true);
        return string.IsNullOrWhiteSpace(cn) ? certificate.Issuer : cn;
    }
}
