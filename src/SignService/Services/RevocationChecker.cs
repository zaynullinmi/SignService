using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;

namespace SignService.Services;

/// <summary>Conservative CRL/OCSP validation. Missing, stale or unverifiable evidence is never "good".</summary>
internal static class RevocationChecker
{
    private static readonly HttpClient Http = new(new HttpClientHandler { AllowAutoRedirect = false })
        { Timeout = TimeSpan.FromSeconds(8) };
    private const int MaxResponseBytes = 4 * 1024 * 1024;

    public static VerificationCheck Check(IReadOnlyList<X509Certificate> chain, IReadOnlyList<X509Crl> embeddedCrls,
        VerificationOptions options, CancellationToken cancellationToken)
    {
        var crls = embeddedCrls.ToList();
        foreach (var bytes in options.Crls)
            try { crls.Add(new X509CrlParser().ReadCrl(bytes)); } catch (Exception) { }
        var unknown = new List<string>();
        for (var i = 0; i + 1 < chain.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var cert = chain[i];
            var issuer = chain[i + 1];
            var evidence = new List<VerificationCheck>();
            foreach (var crl in crls) evidence.Add(CheckCrl(crl, cert, issuer, options.ValidationTime));
            foreach (var response in options.OcspResponses)
                evidence.Add(CheckOcsp(response, cert, issuer, options.ValidationTime));
            if (options.AllowNetwork && !evidence.Any(e => e.State is VerificationState.Valid or VerificationState.Invalid))
            {
                foreach (var uri in OcspUrls(cert).Take(2))
                {
                    var generator = new OcspReqGenerator();
                    generator.AddRequest(new CertificateID(new AlgorithmIdentifier(new DerObjectIdentifier("1.3.14.3.2.26")), issuer, cert.SerialNumber));
                    var response = Download(uri, generator.Generate().GetEncoded(), cancellationToken);
                    if (response is not null) evidence.Add(CheckOcsp(response, cert, issuer, options.ValidationTime));
                }
                foreach (var uri in CrlUrls(cert).Take(2))
                {
                    var response = Download(uri, null, cancellationToken);
                    if (response is null) continue;
                    try { evidence.Add(CheckCrl(new X509CrlParser().ReadCrl(response), cert, issuer, options.ValidationTime)); }
                    catch (Exception) { }
                }
            }
            // Any authenticated evidence of revocation takes precedence over a "good" response.
            var revoked = evidence.FirstOrDefault(e => e.State == VerificationState.Invalid);
            if (revoked is not null) return revoked;
            if (!evidence.Any(e => e.State == VerificationState.Valid)) unknown.Add(cert.SubjectDN.ToString());
        }
        return unknown.Count == 0 ? VerificationCheck.Valid(chain.Count <= 1
                ? "Цепочка состоит из точки доверия; для корневого сертификата отзыв не оценивается."
                : "По свежим подписанным CRL/OCSP сертификаты цепочки не отозваны (корень — точка доверия).")
            : VerificationCheck.Unknown("Нет свежих достоверных CRL/OCSP для: " + string.Join("; ", unknown)
                + (options.AllowNetwork ? ". Запросы в сеть не дали подтверждения." : ". Сетевые запросы отключены."));
    }

    private static VerificationCheck CheckCrl(X509Crl crl, X509Certificate cert, X509Certificate issuer, DateTimeOffset at)
    {
        try
        {
            if (!crl.IssuerDN.Equivalent(issuer.SubjectDN)) return Unknown();
            var usage = issuer.GetKeyUsage();
            if (usage is not null && !usage[6]) return Unknown();
            crl.Verify(issuer.GetPublicKey());
            // Delta, indirect, partitioned or critical CRLs need additional processing. Do not infer "good" from them.
            if (crl.GetExtensionValue(X509Extensions.DeltaCrlIndicator) is not null
                || crl.GetExtensionValue(X509Extensions.IssuingDistributionPoint) is not null
                || crl.GetCriticalExtensionOids() is { Count: > 0 }) return Unknown();
            if (!Fresh(crl.ThisUpdate, crl.NextUpdate, at)) return Unknown();
            var entry = crl.GetRevokedCertificate(cert.SerialNumber);
            if (entry is not null)
            {
                if (entry.GetCriticalExtensionOids() is { Count: > 0 }) return Unknown();
                if (entry.RevocationDate <= at.UtcDateTime)
                    return VerificationCheck.Invalid("Сертификат отозван по подписанному CRL: " + cert.SubjectDN);
            }
            return VerificationCheck.Valid("Свежий CRL издателя: сертификат не отозван.");
        }
        catch (Exception) { return Unknown(); }
    }

    private static VerificationCheck CheckOcsp(byte[] encoded, X509Certificate cert, X509Certificate issuer, DateTimeOffset at)
    {
        try
        {
            var response = new OcspResp(encoded);
            if (response.Status != 0 || response.GetResponseObject() is not BasicOcspResp basic
                || basic.GetCriticalExtensionOids() is { Count: > 0 }
                || basic.ProducedAt > at.UtcDateTime.AddMinutes(5)) return Unknown();
            var responders = basic.GetCerts().Append(issuer);
            var authenticated = responders.Any(responder => AuthorizedResponder(basic, responder, issuer, at));
            if (!authenticated) return Unknown();
            foreach (var single in basic.Responses)
            {
                var id = single.GetCertID();
                if (!id.SerialNumber.Equals(cert.SerialNumber) || !id.MatchesIssuer(issuer)
                    || single.GetCriticalExtensionOids() is { Count: > 0 }
                    || basic.ProducedAt < single.ThisUpdate.AddMinutes(-5)
                    || !Fresh(single.ThisUpdate, single.NextUpdate, at)) continue;
                var status = single.GetCertStatus();
                if (status is RevokedStatus revoked && revoked.RevocationTime <= at.UtcDateTime)
                    return VerificationCheck.Invalid("Сертификат отозван по подписанному OCSP: " + cert.SubjectDN);
                if (status is null) return VerificationCheck.Valid("Свежий OCSP: статус good.");
            }
            return Unknown();
        }
        catch (Exception) { return Unknown(); }
    }

    private static bool AuthorizedResponder(BasicOcspResp response, X509Certificate responder, X509Certificate issuer, DateTimeOffset at)
    {
        try
        {
            if (!response.ResponderId.Equals(new RespID(responder.SubjectDN))
                && !response.ResponderId.Equals(new RespID(responder.GetPublicKey()))) return false;
            if (!responder.Equals(issuer))
            {
                if (!responder.IssuerDN.Equivalent(issuer.SubjectDN)) return false;
                responder.Verify(issuer.GetPublicKey());
                responder.CheckValidity(at.UtcDateTime);
                if (responder.GetExtendedKeyUsage()?.Contains(KeyPurposeID.id_kp_OCSPSigning) != true) return false;
                var usage = responder.GetKeyUsage();
                if (usage is not null && !usage[0]) return false;
                // Unrecognized critical extensions cannot be ignored on a delegated responder.
                var allowed = new[] { X509Extensions.KeyUsage.Id, X509Extensions.ExtendedKeyUsage.Id,
                    X509Extensions.BasicConstraints.Id, OcspObjectIdentifiers.PkixOcspNocheck.Id };
                if (responder.GetCriticalExtensionOids()?.Any(oid => !allowed.Contains(oid)) == true) return false;
            }
            return response.Verify(responder.GetPublicKey());
        }
        catch (Exception) { return false; }
    }

    private static bool Fresh(DateTime thisUpdate, DateTime? nextUpdate, DateTimeOffset at) =>
        thisUpdate <= at.UtcDateTime.AddMinutes(5) && (nextUpdate is { } next
            ? next >= thisUpdate && next >= at.UtcDateTime
            : thisUpdate >= at.UtcDateTime.AddHours(-24));

    private static VerificationCheck Unknown() => VerificationCheck.Unknown("Доказательство отзыва неприменимо, устарело или не прошло проверку.");

    private static IEnumerable<Uri> OcspUrls(X509Certificate cert)
    {
        var ext = cert.GetExtensionValue(X509Extensions.AuthorityInfoAccess);
        if (ext is null) return Array.Empty<Uri>();
        try
        {
            return AuthorityInformationAccess.GetInstance(Asn1Object.FromByteArray(ext.GetOctets())).GetAccessDescriptions()
                .Where(a => a.AccessMethod.Equals(AccessDescription.IdADOcsp)).Select(a => Url(a.AccessLocation)).OfType<Uri>().ToArray();
        }
        catch (Exception) { return Array.Empty<Uri>(); }
    }

    private static IEnumerable<Uri> CrlUrls(X509Certificate cert)
    {
        var ext = cert.GetExtensionValue(X509Extensions.CrlDistributionPoints);
        if (ext is null) return Array.Empty<Uri>();
        try
        {
            return CrlDistPoint.GetInstance(Asn1Object.FromByteArray(ext.GetOctets())).GetDistributionPoints()
                .Where(d => d.DistributionPointName?.Type == DistributionPointName.FullName)
                .SelectMany(d => GeneralNames.GetInstance(d.DistributionPointName.Name).GetNames())
                .Select(Url).OfType<Uri>().ToArray();
        }
        catch (Exception) { return Array.Empty<Uri>(); }
    }

    private static Uri? Url(GeneralName name) => name.TagNo == GeneralName.UniformResourceIdentifier
        && Uri.TryCreate(DerIA5String.GetInstance(name.Name).GetString(), UriKind.Absolute, out var uri)
        && (uri.Scheme == "http" || uri.Scheme == "https") ? uri : null;

    private static byte[]? Download(Uri uri, byte[]? ocspRequest, CancellationToken cancellationToken)
    {
        try
        {
            using var request = new HttpRequestMessage(ocspRequest is null ? HttpMethod.Get : HttpMethod.Post, uri);
            if (ocspRequest is not null)
            {
                request.Content = new ByteArrayContent(ocspRequest);
                request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/ocsp-request");
            }
            using var response = Http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).GetAwaiter().GetResult();
            if (!response.IsSuccessStatusCode || response.Content.Headers.ContentLength > MaxResponseBytes) return null;
            using var stream = response.Content.ReadAsStreamAsync(cancellationToken).GetAwaiter().GetResult();
            using var body = new MemoryStream();
            var buffer = new byte[8192];
            int count;
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(TimeSpan.FromSeconds(8));
            while ((count = stream.ReadAsync(buffer, deadline.Token).AsTask().GetAwaiter().GetResult()) != 0)
            {
                if (body.Length + count > MaxResponseBytes) return null;
                body.Write(buffer, 0, count);
            }
            return body.ToArray();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) { return null; }
    }
}
