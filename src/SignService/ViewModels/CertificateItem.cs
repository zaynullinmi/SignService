using System;
using System.Security.Cryptography.X509Certificates;
using SignService.Services;

namespace SignService.ViewModels;

/// <summary>
/// Элемент списка выбора сертификата: сертификат из системного хранилища
/// (закрытый ключ на токене/в контейнере) либо сохранённый на компьютер PFX
/// (в списке — открытая часть; закрытый ключ загружается по паролю при подписании).
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

    public CertificateItem(SavedCertificateInfo saved)
        : this(CertificateVault.PublicPart(saved))
    {
        Saved = saved;
    }

    /// <summary>
    /// Сертификат: для хранилища — с закрытым ключом, для сохранённого на ПК —
    /// только открытая часть (данные для списка и штампа).
    /// </summary>
    public X509Certificate2 Certificate { get; }

    /// <summary>Метаданные сохранённого на компьютер сертификата (null — из хранилища).</summary>
    public SavedCertificateInfo? Saved { get; }

    public bool IsSaved => Saved is not null;

    /// <summary>
    /// Разблокированный по паролю сертификат сохранённого PFX — кешируется на сеанс,
    /// чтобы при пакетном подписании пароль спрашивался один раз.
    /// </summary>
    public X509Certificate2? Unlocked { get; set; }

    public string Subject { get; }

    public string Issuer { get; }

    public DateTime NotAfter { get; }

    public string Thumbprint { get; }

    public bool IsExpired => NotAfter < DateTime.Now;

    public string DisplayName =>
        $"{Subject} — {Issuer}, до {NotAfter:dd.MM.yyyy}"
        + (IsExpired ? " (истёк)" : string.Empty)
        + (IsSaved ? " — сохранён на ПК 🔒" : string.Empty);
}
