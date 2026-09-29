using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SignService.Services;
using SignService.ViewModels;

internal static class ReviewRegressionTests
{
    public static async Task RunAsync(string tempRoot, DocumentSigner signer)
    {
        var root = Path.Combine(tempRoot, "review_regressions");
        Directory.CreateDirectory(root);
        using var certA = MakeCertificate("CN=Одинаковое Имя, OID.1.2.643.3.131.1.1=771378577706");
        using var certB = MakeCertificate("CN=Одинаковое Имя");
        var current = Encoding.UTF8.GetBytes("current document");
        var previous = Encoding.UTF8.GetBytes("previous document");
        var doc = Path.Combine(root, "document.txt");
        await File.WriteAllBytesAsync(doc, current);

        // Прикреплённая старая версия не должна попасть в новый контейнер.
        await File.WriteAllBytesAsync(doc + ".sig", signer.Sign(previous, certB, detached: false));
        var staleResult = await signer.SignFileAsync(doc, certA, new DocumentSigner.SignOptions
        {
            Detached = false, MergeWithExisting = true,
        });
        Assert(staleResult.ExcludedSigners.Count == 1, "stale signer must be excluded");
        var rebuilt = ReadAttached(staleResult.SignaturePath);
        Assert(rebuilt.ContentInfo.Content.SequenceEqual(current), "old embedded content leaked into new signature");
        Assert(rebuilt.SignerInfos.Count == 1, "wrong signer count after stale merge");
        Console.WriteLine("regression: stale attached input → current attached document verifies: OK");

        // Выбранный откреплённый режим соблюдается даже с прикреплённым входом.
        await File.WriteAllBytesAsync(doc + ".sig", signer.Sign(current, certB, detached: false));
        var detachedResult = await signer.SignFileAsync(doc, certA, new DocumentSigner.SignOptions
        {
            Detached = true, MergeWithExisting = true,
        });
        var detachedBytes = await File.ReadAllBytesAsync(detachedResult.SignaturePath);
        var raw = new SignedCms();
        raw.Decode(detachedBytes);
        Assert(raw.ContentInfo.Content.Length == 0, "detached option ignored");
        var verified = ReadDetached(detachedResult.SignaturePath, current);
        Assert(verified.SignerInfos.Count == 2, "cosigning lost a signer");
        Console.WriteLine("regression: attached input + detached mode → two valid detached signatures: OK");

        // Одинаковые ФИО различаются по идентификатору сертификата.
        var descriptors = CmsExtractor.ListSigners(detachedResult.SignaturePath);
        Assert(descriptors.Count == 2 && descriptors[0].Id != descriptors[1].Id, "signer IDs must be distinct");
        var split = CmsExtractor.SplitSignatureFile(detachedResult.SignaturePath);
        Assert(split.SignerFiles.Count == 2 && split.SignerFiles.Distinct().Count() == 2, "split filenames collide");
        var splitThumbprints = split.SignerFiles.Select(path =>
        {
            var cms = ReadDetached(path, current);
            Assert(cms.SignerInfos.Count == 1, "split must have exactly one signer");
            return cms.SignerInfos[0].Certificate!.Thumbprint;
        }).ToHashSet();
        Assert(splitThumbprints.SetEquals(new[] { certA.Thumbprint, certB.Thumbprint }), "split lost or duplicated a signer");
        var splitAgain = CmsExtractor.SplitSignatureFile(detachedResult.SignaturePath);
        Assert(!splitAgain.SignerFiles.Intersect(split.SignerFiles).Any(), "split overwrote earlier files");
        var removed = CmsExtractor.RemoveSignerFromFile(detachedResult.SignaturePath, descriptors[0].Id);
        Assert(ReadDetached(removed.OutputPath, current).SignerInfos.Count == 1, "remove must leave one valid signer");
        Assert(File.ReadAllBytes(detachedResult.SignaturePath).SequenceEqual(detachedBytes), "remove changed source file");
        ExpectFailure(() => CmsExtractor.RemoveSignerFromFile(removed.OutputPath,
            CmsExtractor.ListSigners(removed.OutputPath)[0].Id), "last signer must be protected");
        ExpectFailure(() => CmsExtractor.RemoveSignerFromFile(detachedResult.SignaturePath, "unknown"), "unknown signer must fail");

        var attachedPath = Path.Combine(root, "attached.sig");
        var merger = typeof(DocumentSigner).Assembly.GetType("SignService.Services.CmsMerger")!;
        var attached = (byte[])merger.GetMethod("AttachContent")!.Invoke(null, new object[] { detachedBytes, current })!;
        await File.WriteAllBytesAsync(attachedPath, attached);
        var attachedRemoved = CmsExtractor.RemoveSignerFromFile(attachedPath, CmsExtractor.ListSigners(attachedPath)[1].Id);
        Assert(ReadAttached(attachedRemoved.OutputPath).ContentInfo.Content.SequenceEqual(current), "remove lost attached document");
        var attachedSplit = CmsExtractor.SplitSignatureFile(attachedPath);
        Assert(attachedSplit.DocumentPath is not null && File.ReadAllBytes(attachedSplit.DocumentPath).SequenceEqual(current), "split lost document");
        foreach (var path in attachedSplit.SignerFiles) ReadDetached(path, current);
        Console.WriteLine("regression: split/remove attached and detached CMS, duplicate names, source preservation: OK");

        var queueItem = new SignFileItem(doc) { Status = SignStatus.Signed, SignerCount = 2, SignaturePath = doc + ".sig" };
        queueItem.AttachSignatures(new[] { removed.OutputPath });
        Assert(queueItem.Status == SignStatus.Pending && queueItem.SignerCount == 0, "new extra signature must requeue file");
        Console.WriteLine("regression: attaching .sig requeues a signed file: OK");

        // Повреждённое signature при неизменном messageDigest должно отвергаться.
        var xmlPath = Path.Combine(root, "poa.xml");
        var sigPath = xmlPath + ".sig";
        var future = DateTime.Today.AddMonths(1).ToString("yyyy-MM-dd");
        string Xml(string until, string inn = "771378577706") =>
            $"<Доверенность><СвДов НомДовер='review' СрокДейст='{until}'/><СвУпПред><СведФизЛ ИННФЛ='{inn}'><ФИО Фамилия='Тест'/></СведФизЛ></СвУпПред></Доверенность>";
        async Task WritePoa(string text)
        {
            await File.WriteAllTextAsync(xmlPath, text);
            await File.WriteAllBytesAsync(sigPath, signer.Sign(await File.ReadAllBytesAsync(xmlPath), certB));
        }
        await WritePoa(Xml(future));
        var cachedPoa = PowerOfAttorneyService.Parse(xmlPath, sigPath);
        Assert(PowerOfAttorneyService.Validate(cachedPoa, certA).State == PowerOfAttorneyService.CheckState.Ok, "valid POA rejected");
        var damaged = await File.ReadAllBytesAsync(sigPath);
        var signatureValue = (byte[])merger.GetMethod("GetSignatureValue")!.Invoke(null, new object[] { damaged })!;
        var offset = Enumerable.Range(0, damaged.Length - signatureValue.Length + 1)
            .First(i => damaged.AsSpan(i, signatureValue.Length).SequenceEqual(signatureValue));
        damaged[offset + signatureValue.Length / 2] ^= 1;
        await File.WriteAllBytesAsync(sigPath, damaged);
        Assert(PowerOfAttorneyService.Validate(cachedPoa, certA).State == PowerOfAttorneyService.CheckState.Error, "tampered signature accepted");
        await WritePoa(Xml("2020-01-01"));
        Assert(PowerOfAttorneyService.Validate(cachedPoa, certA).State == PowerOfAttorneyService.CheckState.Error, "cached expiry bypass");
        await WritePoa(Xml(future, "111111111111"));
        Assert(PowerOfAttorneyService.Validate(cachedPoa, certA).State == PowerOfAttorneyService.CheckState.Error, "cached representative bypass");
        await WritePoa(Xml(future));
        Console.WriteLine("regression: POA rejects damaged signatures and reloads expiry/representative: OK");

        // Коллизия пары файлов должна останавливаться до изменения подписи документа.
        var target = Path.Combine(root, "poa_target");
        Directory.CreateDirectory(target);
        var targetXml = Path.Combine(target, "poa.xml");
        await File.WriteAllTextAsync(targetXml, "unrelated POA");
        ExpectFailure(() => PowerOfAttorneyService.CopyNextToDocument(cachedPoa, Path.Combine(target, "document.txt")), "POA collision must fail");
        Assert(File.ReadAllText(targetXml) == "unrelated POA" && !File.Exists(targetXml + ".sig"), "POA collision wrote a mixed pair");
        var targetDoc = Path.Combine(target, "document.txt");
        await File.WriteAllBytesAsync(targetDoc, current);
        await File.WriteAllBytesAsync(targetDoc + ".sig", detachedBytes);
        try
        {
            await signer.SignFileAsync(targetDoc, certA, new DocumentSigner.SignOptions { PowerOfAttorney = cachedPoa });
            throw new Exception("POA collision must stop signing");
        }
        catch (IOException) { }
        Assert(File.ReadAllBytes(targetDoc + ".sig").SequenceEqual(detachedBytes), "POA failure overwrote existing signature");
        File.Delete(targetXml);
        PowerOfAttorneyService.CopyNextToDocument(cachedPoa, targetDoc);
        PowerOfAttorneyService.CopyNextToDocument(cachedPoa, targetDoc); // одинаковый комплект допускается
        var copy = new SignedCms(new ContentInfo(File.ReadAllBytes(targetXml)), true);
        copy.Decode(File.ReadAllBytes(targetXml + ".sig"));
        copy.CheckSignature(true);
        Console.WriteLine("regression: POA collisions preserve existing files/signature; matching pair is reusable: OK");

        if (OperatingSystem.IsWindows())
            await CheckUpdaterAsync(root);
    }

    private static async Task CheckUpdaterAsync(string root)
    {
        var dir = Path.Combine(root, "update space ' $ % тест");
        Directory.CreateDirectory(dir);
        var current = Path.Combine(dir, "current.exe");
        var downloaded = Path.Combine(dir, "downloaded.exe");
        var build = typeof(UpdateService).GetMethod("BuildInstallScript", BindingFlags.Static | BindingFlags.NonPublic)!;
        async Task<int> Run(bool restart = false)
        {
            var script = (string)build.Invoke(null, new object[] { current, downloaded, 0, restart })!;
            var info = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                "WindowsPowerShell", "v1.0", "powershell.exe"))
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            info.ArgumentList.Add("-NoProfile");
            info.ArgumentList.Add("-NonInteractive");
            info.ArgumentList.Add("-EncodedCommand");
            info.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(script)));
            using var process = Process.Start(info)!;
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            try { await process.WaitForExitAsync(timeout.Token); }
            catch { process.Kill(entireProcessTree: true); throw; }
            await Task.WhenAll(stdout, stderr);
            return process.ExitCode;
        }

        await File.WriteAllTextAsync(current, "working old version");
        Assert(await Run() != 0 && File.ReadAllText(current) == "working old version", "missing download destroyed executable");
        await File.WriteAllTextAsync(downloaded, "new version");
        using (var locked = new FileStream(current, FileMode.Open, FileAccess.Read, FileShare.Read))
            Assert(await Run() != 0, "locked executable must fail safely");
        Assert(File.ReadAllText(current) == "working old version", "failed replacement destroyed executable");
        Assert(await Run() == 0 && File.ReadAllText(current) == "new version", "successful replacement failed");
        Assert(Directory.GetFiles(dir, "*.bak").Any(path => File.ReadAllText(path) == "working old version"), "working backup missing");
        // Текстовый fixture не является EXE: отказ запуска должен восстановить старый файл.
        await File.WriteAllTextAsync(current, "rollback version");
        Assert(await Run(restart: true) != 0 && File.ReadAllText(current) == "rollback version", "restart failure did not roll back");
        Assert(Directory.GetFiles(dir, "*.new").Length == 0, "staging files leaked");
        Console.WriteLine("regression: updater missing source, locked target, replacement/backup and launch rollback: OK");
    }

    private static X509Certificate2 MakeCertificate(string subject)
    {
        using var key = RSA.Create(2048);
        return new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddYears(1));
    }

    private static SignedCms ReadAttached(string path)
    {
        var cms = new SignedCms();
        cms.Decode(File.ReadAllBytes(path));
        cms.CheckSignature(true);
        return cms;
    }

    private static SignedCms ReadDetached(string path, byte[] document)
    {
        var cms = new SignedCms(new ContentInfo(document), true);
        cms.Decode(File.ReadAllBytes(path));
        cms.CheckSignature(true);
        return cms;
    }

    private static void Assert(bool value, string message)
    {
        if (!value) throw new Exception(message);
    }

    private static void ExpectFailure(Action action, string message)
    {
        try { action(); }
        catch (Exception e) when (e is IOException or InvalidOperationException) { return; }
        throw new Exception(message);
    }
}
