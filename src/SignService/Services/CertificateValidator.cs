using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace SignService.Services;

internal sealed record CertificateValidation(VerificationCheck Trust, VerificationCheck Revocation);

internal static class CertificateValidator
{
    public static CertificateValidation Validate(Certificate certificate, IReadOnlyList<Certificate> embedded,
        IReadOnlyList<X509Crl> crls, VerificationOptions options, CancellationToken cancellationToken)
    {
        var notChecked = VerificationCheck.NotChecked("Проверка отключена.");
        if (!options.CheckCertificateTrust && !options.CheckRevocation)
            return new CertificateValidation(notChecked, notChecked);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            certificate.CheckValidity(options.ValidationTime.UtcDateTime);
            var usage = certificate.GetKeyUsage();
            if (usage is not null && !usage[0] && !usage[1])
                return new CertificateValidation(VerificationCheck.Invalid("Сертификат не разрешает подписание."),
                    VerificationCheck.Unknown("Нет допустимой цепочки для проверки отзыва."));
            var parser = new X509CertificateParser();
            var roots = options.TrustedRoots.Select(parser.ReadCertificate).ToList();
            var candidates = embedded.Concat(options.ExtraCertificates.Select(parser.ReadCertificate)).ToList();
            if (options.UseSystemTrustStore)
                foreach (var location in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
                {
                    ReadStore(StoreName.Root, location, roots);
                    ReadStore(StoreName.CertificateAuthority, location, candidates);
                }
            // A root supplied inside a CMS is an intermediate candidate, never a trust anchor.
            roots = roots.Distinct().ToList();
            if (roots.Count == 0)
                return new CertificateValidation(options.CheckCertificateTrust
                    ? VerificationCheck.Unknown("Нет доверенного корневого сертификата. Вложенный корень не создаёт доверия.") : notChecked,
                    options.CheckRevocation ? VerificationCheck.Unknown("Без цепочки до доверенного корня отзыв не подтверждён.") : notChecked);
            var parameters = new PkixBuilderParameters(roots.Select(c => new TrustAnchor(c, null)).ToHashSet(),
                new X509CertStoreSelector { Certificate = certificate })
            {
                Date = options.ValidationTime.UtcDateTime, IsRevocationEnabled = false, MaxPathLength = 8,
            };
            parameters.AddStoreCert(CollectionUtilities.CreateStore(candidates.Append(certificate).Concat(roots)));
            var path = new PkixCertPathBuilder().Build(parameters);
            var root = path.TrustAnchor.TrustedCert;
            root.CheckValidity(options.ValidationTime.UtcDateTime);
            var chain = path.CertPath.Certificates.ToList();
            if (chain.Count == 0 || !chain[^1].Equals(root)) chain.Add(root);
            return new CertificateValidation(options.CheckCertificateTrust
                ? VerificationCheck.Valid($"Цепочка до доверенного корня проверена на {options.ValidationTime:dd.MM.yyyy HH:mm:ss zzz}.") : notChecked,
                options.CheckRevocation ? RevocationChecker.Check(chain, crls, options, cancellationToken) : notChecked);
        }
        catch (OperationCanceledException) { throw; }
        catch (CertificateExpiredException)
        {
            return new CertificateValidation(VerificationCheck.Invalid("Срок сертификата истёк на момент проверки."),
                options.CheckRevocation ? VerificationCheck.Unknown("Отзыв не проверен: сертификат просрочен.") : notChecked);
        }
        catch (CertificateNotYetValidException)
        {
            return new CertificateValidation(VerificationCheck.Invalid("Сертификат ещё не действовал на момент проверки."),
                options.CheckRevocation ? VerificationCheck.Unknown("Отзыв не проверен: сертификат ещё не действовал.") : notChecked);
        }
        catch (Exception e)
        {
            return new CertificateValidation(options.CheckCertificateTrust
                ? VerificationCheck.Unknown("Не удалось построить допустимую цепочку до доверенного корня: " + e.Message) : notChecked,
                options.CheckRevocation ? VerificationCheck.Unknown("Отзыв не подтверждён без допустимой цепочки.") : notChecked);
        }
    }

    private static void ReadStore(StoreName name, StoreLocation location, List<Certificate> destination)
    {
        try
        {
            using var store = new X509Store(name, location);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            foreach (var cert in store.Certificates)
                using (cert)
                    try { destination.Add(new X509CertificateParser().ReadCertificate(cert.RawData)); }
                    catch (Exception) { /* Skip unreadable entries; they cannot establish trust. */ }
        }
        catch (Exception) { /* A platform may not expose both store locations. */ }
    }
}
