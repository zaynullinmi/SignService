using System.Text;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using SignService.Services;
using Certificate = Org.BouncyCastle.X509.X509Certificate;
using ContentInfo = Org.BouncyCastle.Asn1.Cms.ContentInfo;

internal static class VerificationTests
{
    private static int _checks;
    private static readonly DateTime Now = DateTime.UtcNow;
    private static readonly byte[] Data = Encoding.UTF8.GetBytes("Подписанный документ: проверка без криптопровайдера");
    private static readonly VerificationOptions Crypto = new()
        { CheckCertificateTrust = false, CheckRevocation = false, UseSystemTrustStore = false };

    public static async Task RunAsync(string temporaryRoot)
    {
        var rootKey = RsaKey();
        var root = Cert("Root", rootKey, null, rootKey, 1, ca: true);
        var leafKey = RsaKey();
        var leaf = Cert("Signer", leafKey, root, rootKey, 2);
        var otherKey = RsaKey();
        var other = Cert("Other", otherKey, root, rootKey, 3);
        var sig = Sign(Data, leaf, leafKey, new[] { leaf, root });
        var trust = new VerificationOptions { UseSystemTrustStore = false, CheckRevocation = false,
            TrustedRoots = new[] { root.GetEncoded() } };

        var valid = SignatureVerifier.Verify(sig, Data, trust);
        Assert(valid.CryptographicallyValid && valid.Signers[0].CertificateTrust.State == VerificationState.Valid, "RSA and PKIX trusted chain");
        var untrusted = SignatureVerifier.Verify(sig, Data, new VerificationOptions { UseSystemTrustStore = false });
        Assert(untrusted.CryptographicallyValid && untrusted.Signers[0].CertificateTrust.State == VerificationState.Unknown
            && untrusted.Signers[0].Revocation.State == VerificationState.Unknown, "embedded root does not establish trust");
        Assert(SignatureVerifier.Verify(sig, null, Crypto).Signers[0].Signature.State == VerificationState.NotChecked, "detached signature needs original");
        Assert(!SignatureVerifier.Verify(sig, Data.Concat(new byte[] { 1 }).ToArray(), Crypto).CryptographicallyValid, "changed document rejected");
        var damaged = Damage(sig, Data);
        Assert(!SignatureVerifier.Verify(damaged, Data, Crypto).CryptographicallyValid, "changed signature rejected despite intact messageDigest");
        var missingCert = Sign(Data, leaf, leafKey, new[] { root });
        Assert(SignatureVerifier.Verify(missingCert, Data, Crypto).Signers[0].Signature.State == VerificationState.Unknown, "missing signer certificate unknown");
        var unknownAlgorithm = UnknownDigest(sig);
        Assert(SignatureVerifier.Verify(unknownAlgorithm, Data, Crypto).Signers[0].Signature.State == VerificationState.Unknown, "unsupported algorithm unknown rather than valid");
        var otherSig = Sign(Data, other, otherKey, new[] { other, root });
        var merged = CmsMerger.MergeForDocument(new[] { damaged, otherSig }, Data);
        Assert(merged.ExcludedSigners.Count == 1 && merged.SignerCount == 1 && merged.UnverifiedSigners.Count == 0
            && SignatureVerifier.Verify(merged.Signature, Data, Crypto).CryptographicallyValid, "damaged signer excluded from merge");

        var oldData = Encoding.UTF8.GetBytes("Старая версия");
        var oldAttached = Sign(oldData, leaf, leafKey, new[] { leaf }, attached: true);
        var refreshed = CmsMerger.MergeForDocument(new[] { oldAttached, otherSig }, Data);
        Assert(CmsMerger.ExtractContent(refreshed.Signature)!.SequenceEqual(Data)
            && SignatureVerifier.Verify(refreshed.Signature, null, Crypto).CryptographicallyValid, "stale embedded document replaced");
        ExpectFailure(() => CmsMerger.Merge(new[] { oldAttached, Sign(Data, other, otherKey, new[] { other }, attached: true) }),
            "merging different embedded documents without an original is rejected");
        var attached = Sign(Data, leaf, leafKey, new[] { leaf }, attached: true);
        Assert(SignatureVerifier.Verify(attached, null, Crypto).CryptographicallyValid, "attached signature needs no external document");
        Assert(!SignatureVerifier.Verify(attached, oldData, Crypto).CryptographicallyValid, "external and embedded document mismatch rejected");
        var pem = Encoding.ASCII.GetBytes("-----BEGIN PKCS7-----\n" + Convert.ToBase64String(sig) + "\n-----END PKCS7-----");
        Assert(SignatureVerifier.Verify(pem, Data, Crypto).CryptographicallyValid, "PEM accepted");
        Assert(SignatureVerifier.Verify(new byte[] { 0x30, 0x84, 0xff, 0xff, 0xff, 0xff }, Data).Container.State == VerificationState.Invalid, "malformed length returns report");
        var deep = new byte[] { 0x05, 0x00 };
        for (var i = 0; i < 140; i++) deep = new byte[] { 0x30, 0x80 }.Concat(deep).Concat(new byte[] { 0, 0 }).ToArray();
        Assert(SignatureVerifier.Verify(deep, Data).Container.State == VerificationState.Invalid, "deep ASN.1 rejected without stack overflow");
        var wrongBinding = Sign(Data, leaf, leafKey, new[] { leaf }, bindingHash: new byte[32]);
        Assert(SignatureVerifier.Verify(wrongBinding, Data, Crypto).Signers[0].CertificateBinding.State == VerificationState.Invalid,
            "signed but incorrect ESSCertID rejected");
        var noAttrs = Sign(Data, leaf, leafKey, new[] { leaf }, direct: true);
        Assert(SignatureVerifier.Verify(noAttrs, Data, Crypto).CryptographicallyValid, "plain PKCS7 without signedAttrs supported");
        Assert(!SignatureVerifier.Verify(noAttrs, oldData, Crypto).CryptographicallyValid, "direct signature over different bytes rejected");

        var expired = Cert("Expired", leafKey, root, rootKey, 4, notAfter: Now.AddDays(-1));
        var expiry = SignatureVerifier.Verify(Sign(Data, expired, leafKey, new[] { expired }), Data, trust);
        Assert(expiry.CryptographicallyValid && expiry.Signers[0].CertificateTrust.State == VerificationState.Invalid, "expiry separate from mathematical validity");
        var forbidden = Cert("No signing", leafKey, root, rootKey, 5, signingAllowed: false);
        Assert(SignatureVerifier.Verify(Sign(Data, forbidden, leafKey, new[] { forbidden }), Data, trust).Signers[0].CertificateTrust.State == VerificationState.Invalid,
            "key usage enforced");
        var critical = Cert("Critical extension", leafKey, root, rootKey, 6, unknownCritical: true);
        Assert(SignatureVerifier.Verify(Sign(Data, critical, leafKey, new[] { critical }), Data, trust).Signers[0].CertificateTrust.State != VerificationState.Valid,
            "unknown critical certificate extension does not pass PKIX");

        TestRevocation(root, rootKey, leaf, leafKey, sig, trust);
        TestTimestamps(root, rootKey, leaf, leafKey, sig, trust);
        TestGost();
        await TestFiles(temporaryRoot);
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        try { await SignatureVerifier.VerifyAsync(sig, Data, cancellationToken: cancelled.Token); throw new Exception("cancellation ignored"); }
        catch (OperationCanceledException) { Assert(true, "verification cancellation preserved"); }
        Console.WriteLine($"Managed verification regressions: {_checks} checks passed");
    }

    private static void TestRevocation(Certificate root, AsymmetricCipherKeyPair rootKey, Certificate leaf,
        AsymmetricCipherKeyPair leafKey, byte[] sig, VerificationOptions trust)
    {
        VerificationState State(VerificationOptions options) => SignatureVerifier.Verify(sig, Data, options).Signers[0].Revocation.State;
        var goodCrl = Crl(root, rootKey, null);
        var crlOptions = trust with { CheckRevocation = true, Crls = new[] { goodCrl.GetEncoded() } };
        Assert(State(crlOptions) == VerificationState.Valid, "fresh authenticated CRL good");
        Assert(State(crlOptions with { Crls = new[] { Crl(root, rootKey, leaf).GetEncoded() } }) == VerificationState.Invalid, "CRL revoked");
        Assert(State(crlOptions with { Crls = new[] { Crl(root, rootKey, null, stale: true).GetEncoded() } }) == VerificationState.Unknown, "stale CRL unknown");
        Assert(State(crlOptions with { Crls = new[] { Crl(root, leafKey, null).GetEncoded() } }) == VerificationState.Unknown, "CRL forged with wrong key unknown");
        Assert(State(crlOptions with { Crls = new[] { Crl(root, rootKey, null, delta: true).GetEncoded() } }) == VerificationState.Unknown, "delta CRL cannot falsely prove good");

        var ocspOptions = trust with { CheckRevocation = true, OcspResponses = new[] { Ocsp(root, rootKey, leaf) } };
        Assert(State(ocspOptions) == VerificationState.Valid, "fresh issuer OCSP good");
        Assert(State(ocspOptions with { OcspResponses = new[] { Ocsp(root, rootKey, leaf, revoked: true) } }) == VerificationState.Invalid, "OCSP revoked");
        Assert(State(ocspOptions with { OcspResponses = new[] { Ocsp(root, rootKey, leaf, stale: true) } }) == VerificationState.Unknown, "stale OCSP unknown");
        Assert(State(ocspOptions with { OcspResponses = new[] { Ocsp(root, leafKey, leaf) } }) == VerificationState.Unknown, "forged OCSP unknown");
        var otherRootKey = RsaKey(); var otherRoot = Cert("Foreign root", otherRootKey, null, otherRootKey, 7, ca: true);
        Assert(State(ocspOptions with { OcspResponses = new[] { Ocsp(otherRoot, otherRootKey, leaf) } }) == VerificationState.Unknown,
            "OCSP serial alone does not match a different issuer");
        Assert(State(crlOptions with { OcspResponses = new[] { Ocsp(root, rootKey, leaf, revoked: true) } }) == VerificationState.Invalid,
            "authenticated revoked overrides good evidence");
        var responderKey = RsaKey();
        var responder = Cert("OCSP delegate", responderKey, root, rootKey, 8, ocsp: true);
        Assert(State(ocspOptions with { OcspResponses = new[] { Ocsp(root, responderKey, leaf, responder: responder) } }) == VerificationState.Valid,
            "authorized delegated OCSP responder");
        var unauthorized = Cert("Unauthorized delegate", responderKey, root, rootKey, 9);
        Assert(State(ocspOptions with { OcspResponses = new[] { Ocsp(root, responderKey, leaf, responder: unauthorized) } }) == VerificationState.Unknown,
            "delegate without OCSP EKU rejected");
    }

    private static void TestTimestamps(Certificate root, AsymmetricCipherKeyPair rootKey, Certificate leaf,
        AsymmetricCipherKeyPair leafKey, byte[] sig, VerificationOptions trust)
    {
        var tsaKey = RsaKey(); var tsa = Cert("TSA", tsaKey, root, rootKey, 10, tsa: true);
        var signatureValue = CmsMerger.GetSignatureValue(sig);
        var generator = new TimeStampRequestGenerator(); generator.SetCertReq(true);
        var request = generator.Generate("2.16.840.1.101.3.4.2.1", DigestUtilities.CalculateDigest("SHA-256", signatureValue), BigInteger.ValueOf(123));
        var signerInfo = new SignerInfoGeneratorBuilder().Build(new Asn1SignatureFactory("SHA256WITHRSA", tsaKey.Private), tsa);
        var tokenGenerator = new TimeStampTokenGenerator(signerInfo, Asn1DigestFactory.Get(new DerObjectIdentifier("2.16.840.1.101.3.4.2.1")), new DerObjectIdentifier("1.2.3.4"), false);
        tokenGenerator.SetCertificates(CollectionUtilities.CreateStore(new[] { tsa, root }));
        var responseGenerator = new TimeStampResponseGenerator(tokenGenerator, new[] { "2.16.840.1.101.3.4.2.1", "1.2.643.7.1.1.2.2" });
        var response = responseGenerator.Generate(request, BigInteger.One, Now.AddMinutes(-1));
        var token = TimestampClient.ValidateResponse(response.GetEncoded(), request, signatureValue);
        var withTime = CmsMerger.AddUnsignedAttribute(sig, TimestampClient.TimeStampTokenOid, token);
        Assert(SignatureVerifier.Verify(withTime, Data, trust).Signers[0].Timestamp.State == VerificationState.Valid, "trusted TSA token validated");
        var untrusted = trust with { TrustedRoots = Array.Empty<byte[]>() };
        Assert(SignatureVerifier.Verify(withTime, Data, untrusted).Signers[0].Timestamp.State == VerificationState.Unknown, "untrusted TSA token never establishes time");
        var tokenBad = Damage(token, null);
        Assert(SignatureVerifier.Verify(CmsMerger.AddUnsignedAttribute(sig, TimestampClient.TimeStampTokenOid, tokenBad), Data, trust)
            .Signers[0].Timestamp.State == VerificationState.Invalid, "damaged timestamp signature rejected");
        Assert(SignatureVerifier.Verify(CmsMerger.AddUnsignedAttribute(Sign(Data, leaf, leafKey, new[] { leaf }),
            TimestampClient.TimeStampTokenOid, token), Data.Concat(new byte[] { 1 }).ToArray(), trust).CryptographicallyValid == false,
            "timestamp cannot repair wrong document");
        var other = Sign(Data.Concat(new byte[] { 7 }).ToArray(), leaf, leafKey, new[] { leaf });
        Assert(SignatureVerifier.VerifyTimestampToken(token, CmsMerger.GetSignatureValue(other), trust).Check.State == VerificationState.Invalid,
            "TSA imprint bound to exact signature value");
        var wrongNonce = generator.Generate("2.16.840.1.101.3.4.2.1", request.GetMessageImprintDigest(), BigInteger.ValueOf(456));
        ExpectFailure(() => TimestampClient.ValidateResponse(response.GetEncoded(), wrongNonce, signatureValue), "TSA nonce mismatch rejected");
        var gostRequest = generator.Generate("1.2.643.7.1.1.2.2", DigestUtilities.CalculateDigest("1.2.643.7.1.1.2.2", signatureValue), BigInteger.ValueOf(789));
        var gostResponse = responseGenerator.Generate(gostRequest, BigInteger.Two, Now.AddMinutes(-1));
        Assert(TimestampClient.ValidateResponse(gostResponse.GetEncoded(), gostRequest, signatureValue).Length > 0,
            "TSA GOST imprint processed without CryptoPro");
        ExpectFailure(() => TimestampClient.ValidateResponse(response.GetEncoded(), gostRequest, signatureValue), "TSA algorithm/imprint mismatch rejected");
        var futureToken = tokenGenerator.Generate(request, BigInteger.ValueOf(12), Now.AddDays(1)).GetEncoded();
        Assert(SignatureVerifier.VerifyTimestampToken(futureToken, signatureValue, trust).Check.State == VerificationState.Invalid, "future TSA time rejected");
        var expired = Cert("Historically valid signer", leafKey, root, rootKey, 12, notAfter: Now.AddHours(-1));
        var expiredSig = Sign(Data, expired, leafKey, new[] { expired, root });
        var historicalRequest = generator.Generate("2.16.840.1.101.3.4.2.1", DigestUtilities.CalculateDigest("SHA-256", CmsMerger.GetSignatureValue(expiredSig)), BigInteger.ValueOf(13));
        var historicalToken = tokenGenerator.Generate(historicalRequest, BigInteger.ValueOf(13), Now.AddHours(-2)).GetEncoded();
        var historical = CmsMerger.AddUnsignedAttribute(expiredSig, TimestampClient.TimeStampTokenOid, historicalToken);
        Assert(SignatureVerifier.Verify(historical, Data, trust).Signers[0].CertificateTrust.State == VerificationState.Valid,
            "only trusted timestamp permits historical certificate validity");
        Assert(SignatureVerifier.Verify(historical, Data, untrusted).Signers[0].CertificateTrust.State == VerificationState.Invalid,
            "untrusted timestamp cannot bypass current certificate expiry");
    }

    private static void TestGost()
    {
        foreach (var bits in new[] { 2001, 256, 512 })
        {
            var curveOid = bits == 2001 ? CryptoProObjectIdentifiers.GostR3410x2001CryptoProA
                : bits == 256 ? RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA
                : RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA;
            var digestOid = bits == 2001 ? CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet
                : bits == 256 ? RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256 : RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512;
            var curve = ECGost3410NamedCurves.GetByOid(curveOid);
            var parameters = new ECGost3410Parameters(new ECNamedDomainParameters(curveOid, curve), curveOid, digestOid, null);
            var keyGenerator = new ECKeyPairGenerator("ECGOST3410");
            keyGenerator.Init(new ECKeyGenerationParameters(parameters, new SecureRandom()));
            var pair = keyGenerator.GenerateKeyPair();
            var algorithm = bits == 2001 ? "GOST3411WITHECGOST3410" : $"GOST3411-2012-{bits}WITHECGOST3410-2012-{bits}";
            var cert = Cert("GOST " + bits, pair, null, pair, bits, algorithm: algorithm);
            var encoded = Sign(Data, cert, pair, new[] { cert }, algorithm: algorithm);
            Assert(SignatureVerifier.Verify(encoded, Data, Crypto).CryptographicallyValid, "GOST " + bits + " full managed verification");
            Assert(new DocumentSigner().VerifyDetached(Data, encoded), "GOST " + bits + " compatibility API");
            Assert(!SignatureVerifier.Verify(Damage(encoded, Data), Data, Crypto).CryptographicallyValid, "GOST " + bits + " damaged value rejected");
            Assert(!SignatureVerifier.Verify(encoded, Data.Concat(new byte[] { 1 }).ToArray(), Crypto).CryptographicallyValid, "GOST " + bits + " changed document rejected");
            var root = Cert("GOST root " + bits, pair, null, pair, bits + 100, ca: true, algorithm: algorithm);
            var leafPair = keyGenerator.GenerateKeyPair();
            var leaf = Cert("GOST leaf " + bits, leafPair, root, pair, bits + 200, algorithm: algorithm);
            var trust = new VerificationOptions { UseSystemTrustStore = false, CheckRevocation = false, TrustedRoots = new[] { root.GetEncoded() } };
            var chained = SignatureVerifier.Verify(Sign(Data, leaf, leafPair, new[] { leaf, root }, algorithm: algorithm), Data, trust);
            Assert(chained.CryptographicallyValid && chained.Signers[0].CertificateTrust.State == VerificationState.Valid,
                "GOST " + bits + " certificate chain verified without CSP");
        }
        var ec = new ECKeyPairGenerator();
        ec.Init(new ECKeyGenerationParameters(Org.BouncyCastle.Asn1.Sec.SecObjectIdentifiers.SecP256r1, new SecureRandom()));
        var ecPair = ec.GenerateKeyPair();
        var ecCert = Cert("ECDSA", ecPair, null, ecPair, 21, algorithm: "SHA256WITHECDSA");
        Assert(SignatureVerifier.Verify(Sign(Data, ecCert, ecPair, new[] { ecCert }, algorithm: "SHA256WITHECDSA"), Data, Crypto).CryptographicallyValid, "ECDSA verification");
    }

    private static async Task TestFiles(string directory)
    {
        var files = Path.Combine(directory, "verification_regressions"); Directory.CreateDirectory(files);
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Representative, OID.1.2.643.3.131.1.1=123456789012, OID.1.2.643.100.3=12345678901", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var representative = request.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddYears(1));
        using var headRsa = RSA.Create(2048);
        using var head = new CertificateRequest("CN=Head", headRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddYears(1));
        var signer = new DocumentSigner();
        var document = Path.Combine(files, "document.bin"); await File.WriteAllBytesAsync(document, Data);
        var sig = signer.Sign(Data, head, detached: false); await File.WriteAllBytesAsync(document + ".sig", sig);
        var result = await signer.SignFileAsync(document, representative, new DocumentSigner.SignOptions { Detached = true, MergeWithExisting = true });
        Assert(CmsMerger.ExtractContent(await File.ReadAllBytesAsync(result.SignaturePath)) is null && result.SignerCount == 2,
            "selected detached mode preserved when input is attached");
        Assert(signer.VerifyDetached(Data, await File.ReadAllBytesAsync(result.SignaturePath)), "merged detached signatures verify");

        var poaDirectory = Path.Combine(files, "poa"); Directory.CreateDirectory(poaDirectory);
        var xmlPath = Path.Combine(poaDirectory, "power.xml"); var sigPath = xmlPath + ".sig";
        string Xml(DateTime validTo, string snils = "12345678901") => $"<Доверенность><СвДов НомДовер=\"123\" ДатаВыдДовер=\"{DateTime.Today.AddDays(-1):yyyy-MM-dd}\" СрокДейст=\"{validTo:yyyy-MM-dd}\"/><СвРосОрг ИННЮЛ=\"1234567890\"/><СвУпПред><СведФизЛ ИННФЛ=\"123456789012\" СНИЛС=\"{snils}\"><ФИО Фамилия=\"Представитель\"/></СведФизЛ></СвУпПред></Доверенность>";
        async Task WritePoa(string xml)
        {
            await File.WriteAllTextAsync(xmlPath, xml);
            await File.WriteAllBytesAsync(sigPath, signer.Sign(await File.ReadAllBytesAsync(xmlPath), head));
        }
        await WritePoa(Xml(DateTime.Today.AddDays(10)));
        var selected = PowerOfAttorneyService.Parse(xmlPath, sigPath);
        Assert(PowerOfAttorneyService.Validate(selected, representative).State == PowerOfAttorneyService.CheckState.Warning, "untrusted POA head warns");
        using var expiredHead = new CertificateRequest("CN=Expired head", headRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.Now.AddDays(-5), DateTimeOffset.Now.AddDays(-1));
        await File.WriteAllBytesAsync(sigPath, signer.Sign(await File.ReadAllBytesAsync(xmlPath), expiredHead));
        Assert(PowerOfAttorneyService.Validate(selected, head).State == PowerOfAttorneyService.CheckState.Error,
            "missing representative identifiers cannot skip invalid head certificate");
        await WritePoa(Xml(DateTime.Today.AddDays(10)));
        var xmlWithSecondRep = Xml(DateTime.Today.AddDays(10)).Replace("<СвУпПред>",
            "<СвУпПред><СведФизЛ ИННФЛ=\"999999999999\" СНИЛС=\"99999999999\"><ФИО Фамилия=\"Другой\"/></СведФизЛ></СвУпПред><СвУпПред>");
        await WritePoa(xmlWithSecondRep);
        Assert(PowerOfAttorneyService.Prepare(selected, representative).Info.RepresentativeInn == "123456789012",
            "representative selected by identifiers in multi-representative POA");
        await WritePoa(Xml(DateTime.Today.AddDays(10)));
        var headSig = await File.ReadAllBytesAsync(sigPath);
        await File.WriteAllBytesAsync(sigPath, Damage(headSig, await File.ReadAllBytesAsync(xmlPath)));
        Assert(PowerOfAttorneyService.Validate(selected, representative).State == PowerOfAttorneyService.CheckState.Error, "POA damaged signature rejected with same hash");
        await WritePoa(Xml(DateTime.Today.AddDays(-10)));
        Assert(PowerOfAttorneyService.Validate(selected, representative).State == PowerOfAttorneyService.CheckState.Error, "cached POA metadata cannot bypass expired replacement");
        await WritePoa(Xml(DateTime.Today.AddDays(10), "99999999999"));
        Assert(PowerOfAttorneyService.Validate(selected, representative).State == PowerOfAttorneyService.CheckState.Error, "matching INN cannot hide conflicting SNILS");
        await WritePoa(Xml(DateTime.Today.AddDays(10)));
        var preserved = await File.ReadAllBytesAsync(document + ".sig");
        var collision = Path.Combine(files, "power.xml"); await File.WriteAllTextAsync(collision, "unrelated existing file");
        try { await signer.SignFileAsync(document, representative, new DocumentSigner.SignOptions { PowerOfAttorney = selected }); throw new Exception("collision ignored"); }
        catch (IOException) { Assert(true, "POA filename collision fails before signature publication"); }
        Assert((await File.ReadAllBytesAsync(document + ".sig")).SequenceEqual(preserved)
            && await File.ReadAllTextAsync(collision) == "unrelated existing file", "collision leaves existing signature and POA intact");
        File.Delete(collision);
        var package = PowerOfAttorneyService.Prepare(selected, representative);
        await WritePoa(Xml(DateTime.Today.AddDays(-10)));
        PowerOfAttorneyService.CopyPackage(package, document);
        Assert((await File.ReadAllBytesAsync(collision)).SequenceEqual(package.Xml), "POA copy uses verified snapshot after source replacement");
        await File.WriteAllTextAsync(xmlPath, "<!DOCTYPE Доверенность [<!ENTITY x SYSTEM 'file:///missing'>]><Доверенность>&x;</Доверенность>");
        Assert(PowerOfAttorneyService.Validate(selected, representative).State == PowerOfAttorneyService.CheckState.Error, "DTD and external entities rejected");
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        try { await AtomicFile.WriteAsync(document + ".sig", new byte[] { 1 }, cancellationToken: cancelled.Token); throw new Exception("write cancellation ignored"); }
        catch (OperationCanceledException) { Assert(true, "atomic write cancelled"); }
        Assert((await File.ReadAllBytesAsync(document + ".sig")).SequenceEqual(preserved)
            && Directory.GetFiles(files, ".signservice-*.tmp").Length == 0, "cancelled atomic write preserves file and cleans temp");
    }

    private static AsymmetricCipherKeyPair RsaKey()
    {
        var generator = new RsaKeyPairGenerator(); generator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        return generator.GenerateKeyPair();
    }

    private static Certificate Cert(string name, AsymmetricCipherKeyPair key, Certificate? issuer,
        AsymmetricCipherKeyPair issuerKey, int serial, bool ca = false, bool tsa = false, bool ocsp = false,
        DateTime? notAfter = null, bool signingAllowed = true, bool unknownCritical = false, string algorithm = "SHA256WITHRSA")
    {
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(BigInteger.ValueOf(serial));
        generator.SetSubjectDN(new X509Name("CN=" + name)); generator.SetIssuerDN(issuer?.SubjectDN ?? new X509Name("CN=" + name));
        generator.SetNotBefore(Now.AddDays(-5)); generator.SetNotAfter(notAfter ?? Now.AddYears(1)); generator.SetPublicKey(key.Public);
        generator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(ca));
        generator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(ca ? KeyUsage.KeyCertSign | KeyUsage.CrlSign | KeyUsage.DigitalSignature
            : signingAllowed ? KeyUsage.DigitalSignature : KeyUsage.KeyEncipherment));
        if (tsa) generator.AddExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeID.id_kp_timeStamping));
        if (ocsp) generator.AddExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeID.id_kp_OCSPSigning));
        if (unknownCritical) generator.AddExtension(new DerObjectIdentifier("1.2.3.4.5.6.7"), true, DerNull.Instance);
        return generator.Generate(new Asn1SignatureFactory(algorithm, issuerKey.Private));
    }

    private static byte[] Sign(byte[] data, Certificate cert, AsymmetricCipherKeyPair key, Certificate[] certs,
        bool attached = false, bool direct = false, byte[]? bindingHash = null, string algorithm = "SHA256WITHRSA")
    {
        var generator = new CmsSignedDataGenerator(); var builder = new SignerInfoGeneratorBuilder();
        if (direct) builder.SetDirectSignature(true);
        if (bindingHash is not null)
        {
            var id = new Org.BouncyCastle.Asn1.Ess.EssCertIDv2(bindingHash);
            var attr = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(CadesAttributes.SigningCertificateV2Oid),
                new DerSet(new Org.BouncyCastle.Asn1.Ess.SigningCertificateV2(new[] { id })));
            builder.WithSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new Org.BouncyCastle.Asn1.Cms.AttributeTable(new DerSet(attr))));
        }
        generator.AddSignerInfoGenerator(builder.Build(new Asn1SignatureFactory(algorithm, key.Private), cert));
        generator.AddCertificates(CollectionUtilities.CreateStore(certs));
        return generator.Generate(new CmsProcessableByteArray(data), attached).GetEncoded();
    }

    private static byte[] Damage(byte[] encoded, byte[]? data)
    {
        var cms = data is null ? new CmsSignedData(encoded) : new CmsSignedData(new CmsProcessableByteArray(data), encoded);
        var value = cms.GetSignerInfos().GetSigners().First().GetSignature();
        var copy = encoded.ToArray(); var offset = copy.AsSpan().IndexOf(value);
        if (offset < 0) throw new Exception("Signature value missing");
        copy[offset + value.Length - 1] ^= 1; return copy;
    }

    private static byte[] UnknownDigest(byte[] encoded)
    {
        var content = ContentInfo.GetInstance(Asn1Object.FromByteArray(encoded));
        var signed = SignedData.GetInstance(content.Content);
        var signer = SignerInfo.GetInstance(signed.SignerInfos[0]);
        var unknown = new AlgorithmIdentifier(new DerObjectIdentifier("1.2.3.4.999"));
        var changed = new SignerInfo(signer.SignerID, unknown, signer.SignedAttrs,
            signer.SignatureAlgorithm, signer.Signature, signer.UnsignedAttrs);
        return new ContentInfo(content.ContentType, new SignedData(new DerSet(unknown), signed.EncapContentInfo,
            signed.Certificates, signed.CRLs, new DerSet(changed))).GetEncoded();
    }

    private static X509Crl Crl(Certificate issuer, AsymmetricCipherKeyPair key, Certificate? revoked, bool stale = false, bool delta = false)
    {
        var generator = new X509V2CrlGenerator(); generator.SetIssuerDN(issuer.SubjectDN);
        generator.SetThisUpdate(Now.AddHours(-2)); generator.SetNextUpdate(stale ? Now.AddHours(-1) : Now.AddDays(1));
        if (revoked is not null) generator.AddCrlEntry(revoked.SerialNumber, Now.AddHours(-3), CrlReason.KeyCompromise);
        if (delta) generator.AddExtension(X509Extensions.DeltaCrlIndicator, true, DerInteger.ValueOf(1));
        return generator.Generate(new Asn1SignatureFactory("SHA256WITHRSA", key.Private));
    }

    private static byte[] Ocsp(Certificate issuer, AsymmetricCipherKeyPair key, Certificate cert,
        bool revoked = false, bool stale = false, Certificate? responder = null)
    {
        var generator = new BasicOcspRespGenerator((responder ?? issuer).GetPublicKey());
        var id = new CertificateID(new AlgorithmIdentifier(new DerObjectIdentifier("1.3.14.3.2.26")), issuer, cert.SerialNumber);
        generator.AddResponse(id, revoked ? new RevokedStatus(Now.AddHours(-3), CrlReason.KeyCompromise) : null,
            Now.AddHours(-2), stale ? Now.AddHours(-1) : Now.AddDays(1), null);
        var basic = generator.Generate(new Asn1SignatureFactory("SHA256WITHRSA", key.Private), new[] { responder ?? issuer }, Now.AddMinutes(-1));
        return new OcspResp(new Org.BouncyCastle.Asn1.Ocsp.OcspResponse(new Org.BouncyCastle.Asn1.Ocsp.OcspResponseStatus(0),
            new Org.BouncyCastle.Asn1.Ocsp.ResponseBytes(Org.BouncyCastle.Asn1.Ocsp.OcspObjectIdentifiers.PkixOcspBasic,
                new DerOctetString(basic.GetEncoded())))).GetEncoded();
    }

    private static void Assert(bool condition, string scenario)
    {
        if (!condition) throw new Exception("Regression failed: " + scenario);
        _checks++; Console.WriteLine("verification: " + scenario + ": OK");
    }

    private static void ExpectFailure(Action action, string scenario)
    {
        try { action(); }
        catch (Exception) { Assert(true, scenario); return; }
        throw new Exception("Expected rejection: " + scenario);
    }
}
