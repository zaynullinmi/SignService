using System;
using System.Security.Cryptography.X509Certificates;
using SignService.Services;

namespace SignService.ViewModels;

/// <summary>
/// Элемент списка выбора сертификата.
/// </summary>
public class CertificateItem
{
    public CertificateItem(X509Certificate2 certificate)
    {
        Certificate = certificate;
        Subject = CertificateProvider.GetSubjectName(certificate);
        Issuer = CertificateProvider.GetIssuerName(certificate);
        NotAfter = certificate.NotAfter;
        Thumbprint = certificate.Thumbprint;
    }

    public X509Certificate2 Certificate { get; }

    public string Subject { get; }

    public string Issuer { get; }

    public DateTime NotAfter { get; }

    public string Thumbprint { get; }

    public bool IsExpired => NotAfter < DateTime.Now;

    public string DisplayName =>
        $"{Subject} — {Issuer}, до {NotAfter:dd.MM.yyyy}{(IsExpired ? " (истёк)" : string.Empty)}";
}
