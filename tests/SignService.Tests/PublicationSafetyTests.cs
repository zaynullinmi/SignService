using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Wordprocessing;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using SignService.Services;

internal static class PublicationSafetyTests
{
    public static async Task RunAsync(string tempRoot, DocumentSigner signer)
    {
        var root = Path.Combine(tempRoot, "publication-safety");
        Directory.CreateDirectory(root);
        using var a = Certificate("Original signer");
        using var b = Certificate("Concurrent signer");
        using var c = Certificate("Our signer");
        var data = "publication regression"u8.ToArray();
        var original = signer.Sign(data, a);
        var newer = CmsMerger.Merge(new[] { original, signer.Sign(data, b) });

        foreach (var append in new[] { false, true })
        {
            var dir = Directory.CreateDirectory(Path.Combine(root, append ? "append" : "replace")).FullName;
            var document = Path.Combine(dir, "document.txt");
            var signature = document + ".sig";
            await File.WriteAllBytesAsync(document, data);
            await File.WriteAllBytesAsync(signature, original);
            await ExpectChanged(() => signer.SignFileAsync(document, c, new DocumentSigner.SignOptions
            {
                MergeWithExisting = append,
                AfterSignatureInputsRead = () => File.WriteAllBytes(signature, newer),
            }));
            Assert(File.ReadAllBytes(signature).SequenceEqual(newer), "the actual input snapshot must protect a concurrent signer");
            Assert(Directory.GetFiles(dir, "*.bak").Length == 0, "aborting must not produce a misleading backup");

            await File.WriteAllBytesAsync(signature, original);
            await ExpectChanged(() => signer.SignFileAsync(document, c, new DocumentSigner.SignOptions
            {
                MergeWithExisting = append, BeforePublish = () => File.Delete(signature),
            }));
            Assert(!File.Exists(signature), "an external deletion must not be undone");

            var ok = await signer.SignFileAsync(document, c, new DocumentSigner.SignOptions { MergeWithExisting = append });
            Assert(signer.VerifyDetached(data, File.ReadAllBytes(ok.SignaturePath)), "normal creation still works");
            var replacement = await signer.SignFileAsync(document, a, new DocumentSigner.SignOptions { MergeWithExisting = append });
            Assert(replacement.SignerCount == (append ? 2 : 1), "normal append/replacement still works");
            Assert(append || replacement.BackupPath is not null, "intentional replacement retains its backup");
        }

        var appearingDoc = Path.Combine(root, "appearing.txt");
        File.WriteAllBytes(appearingDoc, data);
        await ExpectChanged(() => signer.SignFileAsync(appearingDoc, c, new DocumentSigner.SignOptions
        {
            BeforePublish = () => File.WriteAllBytes(appearingDoc + ".sig", newer),
        }));
        Assert(File.ReadAllBytes(appearingDoc + ".sig").SequenceEqual(newer), "a newly appeared destination must survive");

        var missing = Path.Combine(root, "missing-signature.p7s");
        await ExpectIo(() => signer.SignFileAsync(appearingDoc, c, new DocumentSigner.SignOptions
        {
            MergeWithExisting = true, ExistingSignaturePath = missing,
        }));
        Assert(!File.Exists(missing), "a missing selected file must not silently redirect publication");

        var staged = Path.Combine(root, "staged.sig");
        File.WriteAllBytes(staged, original);
        await ExpectChanged(() => AtomicFile.WriteAsync(staged, signer.Sign(data, c), beforeCommit: () =>
        {
            File.WriteAllBytes(staged, newer);
            DocumentSigner.ThrowIfSignatureChanged(original, File.ReadAllBytes(staged));
        }));
        Assert(File.ReadAllBytes(staged).SequenceEqual(newer), "last check must run after staging and before replacement");
        Assert(!Directory.EnumerateFiles(root, ".signservice-*.tmp").Any(), "cancelled publication cleans its staging file");
        Console.WriteLine("publication: one input snapshot, append/replace changes, deletion, appearance and staging guard: OK");

        foreach (var extension in new[] { ".docx", ".pdf" })
        foreach (var variant in new[] { ".sig", ".p7s", ".p7m", "odd", "direct", "missing-cert", "unrelated" })
        {
            var dir = Directory.CreateDirectory(Path.Combine(root, extension[1..] + "-" + variant.Replace('.', '-'))).FullName;
            var document = Path.Combine(dir, "document" + extension);
            CreateDocument(document);
            var source = File.ReadAllBytes(document);
            var copy = DocumentStamper.CreateStampedCopy(document, new[] { a }, new PdfStamper.StampOptions(), new DateTime(2025, 1, 1));
            var snapshot = File.ReadAllBytes(copy);
            var signaturePath = variant.StartsWith('.') ? copy + variant : Path.Combine(dir, "подпись с другим именем.p7s");
            var signed = variant switch
            {
                "direct" => DirectSignature(snapshot, a),
                "missing-cert" => WithoutCertificate(snapshot, a),
                "unrelated" => signer.Sign("different document"u8.ToArray(), a),
                _ => signer.Sign(snapshot, a),
            };
            File.WriteAllBytes(signaturePath, signed);
            if (variant == "unrelated")
            {
                DocumentStamper.CreateStampedCopy(document, new[] { b }, new PdfStamper.StampOptions(), DateTime.Now);
                Assert(!File.ReadAllBytes(copy).SequenceEqual(snapshot), "an unrelated signature must not prevent a fresh copy");
                continue;
            }

            ExpectSignedCopy(() => DocumentStamper.CreateStampedCopy(document, new[] { b }, new PdfStamper.StampOptions(), DateTime.Now));
            await ExpectSignedCopyAsync(() => signer.SignFileAsync(document, b, new DocumentSigner.SignOptions { Stamp = true }));
            await ExpectSignedCopyAsync(() => signer.SignFileAsync(document, b, new DocumentSigner.SignOptions { Stamp = true, StampSignCopy = true }));
            // Direct callers of the format stampers must also be protected at commit time.
            ExpectSignedCopy(() => extension == ".pdf"
                ? PdfStamper.CreateStampedCopy(document, new[] { b }, new PdfStamper.StampOptions(), DateTime.Now)
                : WordStamper.CreateStampedCopy(document, new[] { b }, new PdfStamper.StampOptions(), DateTime.Now));
            Assert(File.ReadAllBytes(copy).SequenceEqual(snapshot) && File.ReadAllBytes(document).SequenceEqual(source),
                "guarded stamping must preserve both documents");
            Assert(File.ReadAllBytes(signaturePath).SequenceEqual(signed), "guarded stamping must preserve the original signature");
            Assert(!File.Exists(document + ".sig"), "preflight must stop signing before creating a new signature");
        }
        Console.WriteLine("publication: PDF/Word signed copies protected for sig/p7s/p7m, odd names, direct CMS and missing certificates: OK");
    }

    private static byte[] DirectSignature(byte[] data, X509Certificate2 certificate)
    {
        using var rsa = certificate.GetRSAPrivateKey()!;
        var key = DotNetUtilities.GetRsaKeyPair(rsa);
        var cert = new X509CertificateParser().ReadCertificate(certificate.RawData);
        var generator = new CmsSignedDataGenerator();
        generator.AddSignerInfoGenerator(new SignerInfoGeneratorBuilder().SetDirectSignature(true)
            .Build(new Asn1SignatureFactory("SHA256WITHRSA", key.Private), cert));
        generator.AddCertificates(Org.BouncyCastle.Utilities.Collections.CollectionUtilities.CreateStore(new[] { cert }));
        return generator.Generate(new CmsProcessableByteArray(data), false).GetEncoded();
    }

    private static byte[] WithoutCertificate(byte[] data, X509Certificate2 certificate)
    {
        var cms = new SignedCms(new ContentInfo(data), true);
        var signer = new CmsSigner(certificate) { IncludeOption = X509IncludeOption.None };
        signer.SignedAttributes.Add(new Pkcs9SigningTime());
        cms.ComputeSignature(signer);
        return cms.Encode();
    }

    private static void CreateDocument(string path)
    {
        if (path.EndsWith(".pdf", StringComparison.Ordinal))
        {
            using var pdf = new PdfSharp.Pdf.PdfDocument();
            pdf.AddPage();
            pdf.Save(path);
            return;
        }
        using var document = WordprocessingDocument.Create(path, WordprocessingDocumentType.Document);
        document.AddMainDocumentPart().Document = new Document(new Body(new Paragraph(new Run(new Text("Original content"))), new SectionProperties()));
    }

    private static X509Certificate2 Certificate(string name)
    {
        using var key = RSA.Create(2048);
        return new CertificateRequest("CN=" + name, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(1));
    }

    private static async Task ExpectChanged(Func<Task> operation)
    {
        try { await operation(); }
        catch (IOException e) when (e.Message.Contains("изменился")) { return; }
        throw new Exception("Concurrent publication must be rejected");
    }

    private static async Task ExpectIo(Func<Task> operation)
    {
        try { await operation(); }
        catch (IOException) { return; }
        throw new Exception("Missing input must be rejected");
    }

    private static void ExpectSignedCopy(Func<string> operation)
    {
        try { operation(); }
        catch (InvalidOperationException e) when (e.Message.Contains("уже подписана")) { return; }
        throw new Exception("Signed copy must be protected");
    }

    private static async Task ExpectSignedCopyAsync(Func<Task> operation)
    {
        try { await operation(); }
        catch (InvalidOperationException e) when (e.Message.Contains("уже подписана")) { return; }
        throw new Exception("Signing must preserve the signed copy");
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new Exception("Publication regression: " + message);
    }
}
