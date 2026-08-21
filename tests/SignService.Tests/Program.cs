// Интеграционные тесты SignService: Стрибог, подпись CAdES-BES, соподписание,
// нормализация BER, извлечение из контейнера, штамп времени (CAdES-T, локальный
// TSA-ответчик на openssl), визуальный штамп на PDF и объединение без подписания.
// Запуск: dotnet run --project tests/SignService.Tests -c Release
// Криптография — managed-путь (RSA); нативный ГОСТ-путь (CryptSignMessage)
// проверяется вручную на Windows с КриптоПро.
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using SignService.Services;

var tempRoot = Path.Combine(Path.GetTempPath(), "signservice_tests_" + Guid.NewGuid().ToString("N")[..8]);
Directory.CreateDirectory(tempRoot);

var mergerType = typeof(DocumentSigner).Assembly.GetType("SignService.Services.CmsMerger")!;
var streebogType = typeof(DocumentSigner).Assembly.GetType("SignService.Services.Streebog")!;
var h256 = streebogType.GetMethod("Hash256")!;
var h512 = streebogType.GetMethod("Hash512")!;
var mergeMethod = mergerType.GetMethod("Merge")!;
var countMethod = mergerType.GetMethod("CountSigners")!;
byte[] Merge(params byte[][] sigs) => (byte[])mergeMethod.Invoke(null, new object[] { sigs })!;
int CountSigners(byte[] s) => (int)countMethod.Invoke(null, new object[] { s })!;

// ===== 1. Стрибог: RFC 6986 + случайные векторы от эталонной реализации =====
var vecPath = Path.Combine(AppContext.BaseDirectory, "streebog_vectors.json");
var vectors = JsonDocument.Parse(File.ReadAllText(vecPath)).RootElement;
var vectorCount = 0;
foreach (var v in vectors.EnumerateArray())
{
    var data = Convert.FromHexString(v.GetProperty("data").GetString()!);
    var e256 = v.GetProperty("h256").GetString()!;
    var e512 = v.GetProperty("h512").GetString()!;
    var a256 = Convert.ToHexString((byte[])h256.Invoke(null, new object[] { data })!).ToLowerInvariant();
    var a512 = Convert.ToHexString((byte[])h512.Invoke(null, new object[] { data })!).ToLowerInvariant();
    if (a256 != e256) throw new Exception($"Streebog256 mismatch for {data.Length} bytes");
    if (a512 != e512) throw new Exception($"Streebog512 mismatch for {data.Length} bytes");
    vectorCount++;
}
Console.WriteLine($"Streebog-256/512: {vectorCount} vectors OK (incl. RFC 6986 M1/M2)");

// ===== 2. Подпись RSA-сертификатом: CAdES-атрибуты присутствуют =====
X509Certificate2 MakeCert(string cn)
{
    using var key = RSA.Create(2048);
    var req = new CertificateRequest($"CN={cn}, O=SignService Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    return req.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddYears(1));
}

using var cert = MakeCert("Тестовый Пользователь");
using var certB = MakeCert("Подписант Б");
using var certC = MakeCert("Подписант В");

var signer = new DocumentSigner();
var payload = new byte[128 * 1024];
Random.Shared.NextBytes(payload);

var sig = signer.Sign(payload, cert, detached: true);
var cms = new SignedCms(new ContentInfo(payload), detached: true);
cms.Decode(sig);
cms.CheckSignature(verifySignatureOnly: true);
Console.WriteLine("detached sign + verify: OK");

var si = cms.SignerInfos[0];
byte[]? certV2Der = null;
var hasTime = false;
foreach (CryptographicAttributeObject attr in si.SignedAttributes)
{
    if (attr.Oid.Value == "1.2.840.113549.1.9.5") hasTime = true;
    if (attr.Oid.Value == "1.2.840.113549.1.9.16.2.47") certV2Der = attr.Values[0].RawData;
}
if (!hasTime) throw new Exception("no signing-time attribute");
if (certV2Der is null) throw new Exception("no signing-certificate-v2 attribute");
if (certV2Der.AsSpan().IndexOf(SHA256.HashData(cert.RawData)) < 0)
    throw new Exception("certHash (SHA-256 of cert) not found in signing-certificate-v2");
if (certV2Der.AsSpan().IndexOf(cert.SerialNumberBytes.Span) < 0)
    throw new Exception("serial number not found in signing-certificate-v2");
Console.WriteLine("CAdES-BES attributes: signing-time + signing-certificate-v2 (hash, serial): OK");

// ===== 3. Испорченные данные не проходят проверку =====
payload[0] ^= 0xFF;
if (signer.VerifyDetached(payload, sig)) throw new Exception("tampered data verified!");
payload[0] ^= 0xFF;
Console.WriteLine("tampered data rejected: OK");

// ===== 4. Прикреплённая подпись: документ извлекается, атрибуты на месте =====
var attachedA = signer.Sign(payload, cert, detached: false);
var cms2 = new SignedCms();
cms2.Decode(attachedA);
cms2.CheckSignature(verifySignatureOnly: true);
if (!cms2.ContentInfo.Content.AsSpan().SequenceEqual(payload)) throw new Exception("attached content mismatch");
Console.WriteLine("attached sign/verify + content roundtrip: OK");

// ===== 5. SignFileAsync создаёт .sig =====
var testFile = Path.Combine(tempRoot, "документ.bin");
await File.WriteAllBytesAsync(testFile, payload);
var fileResult = await signer.SignFileAsync(testFile, cert, detached: true);
if (fileResult.SignaturePath != testFile + ".sig" || !File.Exists(fileResult.SignaturePath))
    throw new Exception("sig file not created");
if (fileResult.SignerCount != 1) throw new Exception("expected 1 signer");
Console.WriteLine("SignFileAsync: OK");

// ===== 6. Объединение подписей (соподписание) =====
var sigA = signer.Sign(payload, cert, detached: true);
var sigB = signer.Sign(payload, certB, detached: true);
var sigC = signer.Sign(payload, certC, detached: true);

var merged3 = Merge(Merge(sigA, sigB), sigC);
var cmsM3 = new SignedCms(new ContentInfo(payload), detached: true);
cmsM3.Decode(merged3);
if (cmsM3.SignerInfos.Count != 3) throw new Exception("merged3: expected 3 signers");
cmsM3.CheckSignature(verifySignatureOnly: true);
Console.WriteLine("merge 3 signatures (incremental): 3 signers, all verify: OK");

var mergedDedup = Merge(merged3, signer.Sign(payload, cert, detached: true));
if (CountSigners(mergedDedup) != 3) throw new Exception("re-sign by same signer must replace, not duplicate");
Console.WriteLine("same-signer re-sign replaces (still 3 signers): OK");

var b64Input = System.Text.Encoding.ASCII.GetBytes(Convert.ToBase64String(sigB));
if (CountSigners(Merge(sigA, b64Input)) != 2) throw new Exception("base64 signature input failed");
Console.WriteLine("base64 .sig input normalized: OK");

// ===== 7. BER: неопределённая длина, длинные формы, хвост =====
byte[] ToIndefinite(byte[] der)
{
    int Convert(ReadOnlySpan<byte> s, MemoryStream o)
    {
        var p = 0;
        var b0 = s[p++];
        if ((b0 & 0x1F) == 0x1F) { while ((s[p] & 0x80) != 0) p++; p++; }
        var tagLen = p;
        var constructed = (b0 & 0x20) != 0;
        var lb = s[p++];
        int len;
        if (lb < 0x80) len = lb;
        else { var n = lb & 0x7F; len = 0; for (var i = 0; i < n; i++) len = (len << 8) | s[p++]; }
        if (constructed)
        {
            o.Write(s[..tagLen]); o.WriteByte(0x80);
            var children = s.Slice(p, len); var q = 0;
            while (q < children.Length) q += Convert(children[q..], o);
            o.WriteByte(0x00); o.WriteByte(0x00);
        }
        else
        {
            o.Write(s[..tagLen]);
            if (len < 0x80) { o.WriteByte(0x81); o.WriteByte((byte)len); }
            else { o.WriteByte(0x82); o.WriteByte((byte)(len >> 8)); o.WriteByte((byte)(len & 0xFF)); }
            o.Write(s.Slice(p, len));
        }
        return p + len;
    }
    var ms = new MemoryStream();
    Convert(der, ms);
    return ms.ToArray();
}

var berSigB = ToIndefinite(sigB);
if (berSigB[1] != 0x80) throw new Exception("expected indefinite length at top level");
var mergedBer = Merge(sigA, berSigB);
var cmsBer = new SignedCms(new ContentInfo(payload), detached: true);
cmsBer.Decode(mergedBer);
if (cmsBer.SignerInfos.Count != 2) throw new Exception("indefinite BER merge failed");
cmsBer.CheckSignature(verifySignatureOnly: true);
Console.WriteLine("indefinite-length BER .sig merged + verified: OK");

var trailing = sigB.Concat(new byte[] { 0x0D, 0x0A, 0x00, 0x00 }).ToArray();
if (CountSigners(Merge(sigA, trailing)) != 2) throw new Exception("trailing bytes input failed");
var norm = (byte[])mergerType.GetMethod("Normalize")!.Invoke(null, new object[] { sigA })!;
if (!norm.SequenceEqual(sigA)) throw new Exception("normalize must be identity on canonical DER");
Console.WriteLine("trailing bytes tolerated; normalize is identity on DER: OK");

// ===== 8. Подпись под другой версией документа исключается при объединении =====
var stalePayload = payload.ToArray();
stalePayload[0] ^= 0xFF;
using var certStale = MakeCert("Устаревший Подписант");
var sigStale = signer.Sign(stalePayload, certStale, detached: true);

var extraPath = Path.Combine(tempRoot, "colleague.sig");
await File.WriteAllBytesAsync(extraPath, sigC);
await File.WriteAllBytesAsync(testFile + ".sig", Merge(sigB, sigStale));
var coSign = await signer.SignFileAsync(testFile, cert, detached: true,
    mergeWithExisting: true, extraSignatures: new[] { extraPath });
if (coSign.SignerCount != 3) throw new Exception($"co-sign: {coSign.SignerCount} signers, expected 3");
if (coSign.ExcludedSigners.Count != 1 || !coSign.ExcludedSigners[0].Contains("Устаревший Подписант"))
    throw new Exception("stale signer not reported");
var cmsClean = new SignedCms(new ContentInfo(payload), detached: true);
cmsClean.Decode(await File.ReadAllBytesAsync(coSign.SignaturePath));
cmsClean.CheckSignature(verifySignatureOnly: true);
Console.WriteLine($"stale signature excluded by name ({coSign.ExcludedSigners[0]}), 3 valid signers: OK");

try
{
    mergerType.GetMethod("MergeForDocument")!.Invoke(null, new object[] { new[] { sigStale }, payload });
    throw new Exception("expected failure when all signatures mismatch");
}
catch (TargetInvocationException e)
    when (e.InnerException is InvalidOperationException ioe && ioe.Message.Contains("не соответствуют"))
{
    Console.WriteLine("all-mismatch merge fails with clear error: OK");
}

var hashDoc = mergerType.GetMethod("HashDocument", BindingFlags.NonPublic | BindingFlags.Static)!;
var gostHash = (byte[]?)hashDoc.Invoke(null, new object?[] { "1.2.643.7.1.1.2.2", payload });
var expected256 = (byte[])h256.Invoke(null, new object[] { payload })!;
if (gostHash is null || !gostHash.SequenceEqual(expected256)) throw new Exception("GOST doc hash path broken");
Console.WriteLine("GOST digest OID → Streebog-256 doc hash: OK");

// ===== 9. Извлечение из криптоконтейнера =====
var extractDir = Path.Combine(tempRoot, "extract");
Directory.CreateDirectory(extractDir);
var attachedMerged = Merge(attachedA, signer.Sign(payload, certB, detached: false));
var containerPath = Path.Combine(extractDir, "акт.pdf.sig");
await File.WriteAllBytesAsync(containerPath, attachedMerged);

var extraction = CmsExtractor.ExtractToFiles(containerPath);
if (!extraction.WasAttached || extraction.SignerCount != 2) throw new Exception("extraction info wrong");
if (extraction.DocumentPath is null || Path.GetFileName(extraction.DocumentPath) != "акт.pdf")
    throw new Exception("document not extracted as акт.pdf");
if (!(await File.ReadAllBytesAsync(extraction.DocumentPath)).SequenceEqual(payload))
    throw new Exception("document bytes mismatch");

var cmsDet = new SignedCms(new ContentInfo(payload), detached: true);
cmsDet.Decode(await File.ReadAllBytesAsync(extraction.DetachedPath!));
if (cmsDet.SignerInfos.Count != 2) throw new Exception("detached must keep both signers");
cmsDet.CheckSignature(verifySignatureOnly: true);

if (extraction.SignerFiles.Count != 2) throw new Exception("expected 2 per-signer files");
foreach (var sf in extraction.SignerFiles)
{
    var one = new SignedCms(new ContentInfo(payload), detached: true);
    one.Decode(await File.ReadAllBytesAsync(sf));
    if (one.SignerInfos.Count != 1) throw new Exception("per-signer file must contain exactly 1 signer");
    one.CheckSignature(verifySignatureOnly: true);
}
if (!extraction.SignerFiles.Any(f => f.Contains("Подписант Б")))
    throw new Exception("per-signer file names must contain signer CN");

var extraction2 = CmsExtractor.ExtractToFiles(containerPath);
if (extraction2.DocumentPath == extraction.DocumentPath) throw new Exception("must not overwrite");

var detOnePath = Path.Combine(extractDir, "одиночная.sig");
await File.WriteAllBytesAsync(detOnePath, sigA);
var extraction3 = CmsExtractor.ExtractToFiles(detOnePath);
if (extraction3.WasAttached || extraction3.DocumentPath is not null || extraction3.SignerFiles.Count != 0)
    throw new Exception("detached single-signer must extract nothing");
Console.WriteLine("extract: document byte-exact, detached verifies, per-signer split, no overwrite: OK");

// ===== 10. Штамп времени (CAdES-T) через локальный TSA на openssl =====
if (OpensslAvailable())
{
    using var tsa = await LocalTsa.StartAsync(Path.Combine(tempRoot, "tsa"));
    File.Delete(testFile + ".sig");
    var tsResult = await signer.SignFileAsync(testFile, cert, new DocumentSigner.SignOptions
    {
        Detached = true,
        Timestamp = true,
        TsaUrl = tsa.Url,
    });
    var tsSig = await File.ReadAllBytesAsync(tsResult.SignaturePath);
    var cmsTs = new SignedCms(new ContentInfo(payload), detached: true);
    cmsTs.Decode(tsSig);
    cmsTs.CheckSignature(verifySignatureOnly: true);
    var tsAttr = cmsTs.SignerInfos[0].UnsignedAttributes.Cast<CryptographicAttributeObject>()
        .FirstOrDefault(a => a.Oid.Value == "1.2.840.113549.1.9.16.2.14")
        ?? throw new Exception("no timeStampToken unsigned attribute");
    if (!Rfc3161TimestampToken.TryDecode(tsAttr.Values[0].RawData, out var tst, out _))
        throw new Exception("timeStampToken does not decode");
    if (Math.Abs((tst!.TokenInfo.Timestamp - DateTimeOffset.UtcNow).TotalMinutes) > 5)
        throw new Exception("timestamp drift too large");
    var sigValue = (byte[])mergerType.GetMethod("GetSignatureValue")!.Invoke(null, new object[] { tsSig })!;
    if (!tst.TokenInfo.GetMessageHash().ToArray().SequenceEqual(SHA256.HashData(sigValue)))
        throw new Exception("timestamp messageImprint != SHA256(signature value)");
    Console.WriteLine($"CAdES-T: token embedded ({tst.TokenInfo.Timestamp:dd.MM.yyyy HH:mm:ss} UTC), imprint matches: OK");

    // штамп времени + соподписание совместимы
    await File.WriteAllBytesAsync(testFile + ".sig", sigB);
    var tsMerge = await signer.SignFileAsync(testFile, cert, new DocumentSigner.SignOptions
    {
        Detached = true,
        MergeWithExisting = true,
        Timestamp = true,
        TsaUrl = tsa.Url,
    });
    if (tsMerge.SignerCount != 2) throw new Exception("timestamp + merge failed");
    var cmsTsM = new SignedCms(new ContentInfo(payload), detached: true);
    cmsTsM.Decode(await File.ReadAllBytesAsync(tsMerge.SignaturePath));
    cmsTsM.CheckSignature(verifySignatureOnly: true);
    if (!cmsTsM.SignerInfos.Cast<SignerInfo>().Any(s => s.UnsignedAttributes.Cast<CryptographicAttributeObject>()
            .Any(a => a.Oid.Value == "1.2.840.113549.1.9.16.2.14")))
        throw new Exception("timestamp attribute lost after merge");
    Console.WriteLine("CAdES-T + co-signing: 2 signers, token survives merge: OK");
}
else
{
    Console.WriteLine("CAdES-T: SKIPPED (openssl not found)");
}

// ===== 11. Визуальный штамп на PDF с логотипом =====
var pdfDir = Path.Combine(tempRoot, "stamp");
Directory.CreateDirectory(pdfDir);
var pdfPath = Path.Combine(pdfDir, "договор.pdf");

_ = PdfStamper.IsPdf(pdfPath); // инициализация FontResolver до создания PDF
{
    using var doc = new PdfSharp.Pdf.PdfDocument();
    for (var i = 0; i < 2; i++)
    {
        var page = doc.AddPage();
        using var g = PdfSharp.Drawing.XGraphics.FromPdfPage(page);
        g.DrawString($"Страница {i + 1} — тестовый договор", new PdfSharp.Drawing.XFont("stamp", 14),
            PdfSharp.Drawing.XBrushes.Black, 60, 60);
    }
    doc.Save(pdfPath);
}

// логотип: PNG с прозрачностью (проверяет перекодирование через SkiaSharp)
var logoPath = Path.Combine(pdfDir, "logo.png");
{
    using var surface = SkiaSharp.SKSurface.Create(new SkiaSharp.SKImageInfo(96, 96));
    surface.Canvas.Clear(SkiaSharp.SKColors.Transparent);
    using var paint = new SkiaSharp.SKPaint { Color = new SkiaSharp.SKColor(0x1B, 0x4F, 0x9C), IsAntialias = true };
    surface.Canvas.DrawCircle(48, 48, 44, paint);
    using var snap = surface.Snapshot();
    using var png = snap.Encode(SkiaSharp.SKEncodedImageFormat.Png, 100);
    await File.WriteAllBytesAsync(logoPath, png.ToArray());
}

var stampResult = await signer.SignFileAsync(pdfPath, cert, new DocumentSigner.SignOptions
{
    Detached = true,
    Stamp = true,
    StampWithDate = true,
    StampLogoPath = logoPath,
});
var stampedPath = Path.Combine(pdfDir, "договор (со штампом).pdf");
if (stampResult.SignedDocumentPath != stampedPath || !File.Exists(stampedPath))
    throw new Exception("stamped copy not created");
if (stampResult.SignaturePath != stampedPath + ".sig") throw new Exception("signature must target stamped copy");
if (!File.Exists(pdfPath)) throw new Exception("original PDF must remain");

var stampedBytes = await File.ReadAllBytesAsync(stampedPath);
var cmsStamp = new SignedCms(new ContentInfo(stampedBytes), detached: true);
cmsStamp.Decode(await File.ReadAllBytesAsync(stampResult.SignaturePath));
cmsStamp.CheckSignature(verifySignatureOnly: true);
Console.WriteLine("PDF stamp: stamped copy created, signature verifies over stamped bytes: OK");

var res2 = await signer.SignFileAsync(pdfPath, cert, new DocumentSigner.SignOptions
{
    Detached = true, Stamp = true, StampWithDate = false,
});
if (!File.Exists(res2.SignedDocumentPath)) throw new Exception("no-date stamp failed");

var txtFile = Path.Combine(pdfDir, "заметка.txt");
await File.WriteAllBytesAsync(txtFile, payload);
var txtRes = await signer.SignFileAsync(txtFile, cert, new DocumentSigner.SignOptions
{
    Detached = true, Stamp = true,
});
if (txtRes.SignedDocumentPath != txtFile) throw new Exception("non-PDF must be signed as-is");

var fakePdf = Path.Combine(pdfDir, "битый.pdf");
await File.WriteAllBytesAsync(fakePdf, new byte[] { 1, 2, 3 });
try
{
    await signer.SignFileAsync(fakePdf, cert, new DocumentSigner.SignOptions { Stamp = true });
    throw new Exception("broken PDF must fail");
}
catch (InvalidOperationException e) when (e.Message.Contains("штамп"))
{
}
Console.WriteLine("PDF stamp variants (no date/logo, non-PDF, broken PDF): OK");

// ===== 12. Объединение подписей без подписания =====
var mDir = Path.Combine(tempRoot, "merge_files");
Directory.CreateDirectory(mDir);

// а) откреплённые + документ рядом: проверка по документу, протухшая исключается
var mDoc = Path.Combine(mDir, "справка.pdf");
await File.WriteAllBytesAsync(mDoc, payload);
var p1 = Path.Combine(mDir, "справка.pdf.sig");
var p2 = Path.Combine(mDir, "справка.pdf (Б).sig");
var p3 = Path.Combine(mDir, "справка.pdf (устаревшая).sig");
await File.WriteAllBytesAsync(p1, sigA);
await File.WriteAllBytesAsync(p2, sigB);
await File.WriteAllBytesAsync(p3, sigStale);
var mr1 = CmsExtractor.MergeSignatureFiles(new[] { p1, p2, p3 });
if (mr1.SignerCount != 2 || mr1.AttachedOutput) throw new Exception("file merge: wrong result");
if (mr1.ExcludedSigners.Count != 1) throw new Exception("stale must be excluded in file merge");
if (!mr1.DocumentNote.Contains("справка.pdf")) throw new Exception("document note missing");
var mCms1 = new SignedCms(new ContentInfo(payload), detached: true);
mCms1.Decode(await File.ReadAllBytesAsync(mr1.OutputPath));
mCms1.CheckSignature(verifySignatureOnly: true);
Console.WriteLine($"merge w/o signing (detached + doc nearby): 2 valid signers, stale excluded → {Path.GetFileName(mr1.OutputPath)}");

// б) прикреплённый контейнер + откреплённая: документ из контейнера, результат прикреплённый
var pa = Path.Combine(mDir, "контейнер.sig");
await File.WriteAllBytesAsync(pa, attachedA);
var pb = Path.Combine(mDir, "отдельная.sig");
await File.WriteAllBytesAsync(pb, sigB);
var mr2 = CmsExtractor.MergeSignatureFiles(new[] { pa, pb });
if (mr2.SignerCount != 2 || !mr2.AttachedOutput) throw new Exception("attached merge failed");
if (!mr2.DocumentNote.Contains("контейнер")) throw new Exception("doc source note wrong");
var mCms2 = new SignedCms();
mCms2.Decode(await File.ReadAllBytesAsync(mr2.OutputPath));
mCms2.CheckSignature(verifySignatureOnly: true);
if (!mCms2.ContentInfo.Content.AsSpan().SequenceEqual(payload)) throw new Exception("attached merge lost document");
Console.WriteLine("merge w/o signing (attached + detached): attached output, doc preserved, 2 signers verify");

// в) документа нет — механическое объединение с пометкой
var q1 = Path.Combine(mDir, "неизвестно1.sig");
var q2 = Path.Combine(mDir, "неизвестно2.sig");
await File.WriteAllBytesAsync(q1, sigA);
await File.WriteAllBytesAsync(q2, sigC);
var mr3 = CmsExtractor.MergeSignatureFiles(new[] { q1, q2 });
if (mr3.SignerCount != 2 || !mr3.DocumentNote.Contains("не проверялось")) throw new Exception("no-doc merge failed");
Console.WriteLine("merge w/o signing (no document): mechanical merge with note: OK");

// г) один файл — понятная ошибка
try
{
    CmsExtractor.MergeSignatureFiles(new[] { q1 });
    throw new Exception("single file must fail");
}
catch (ArgumentException)
{
    Console.WriteLine("merge w/o signing: <2 files → clear error: OK");
}

// ===== 13. Хранилище сертификатов на компьютере (PFX с паролем) =====
var vault = new CertificateVault();
var vaultSettings = new AppSettings(); // пишет в реальный %AppData% — тестовые записи чистим ниже

var savedInfo = vault.Save(cert, "test-пароль-123", vaultSettings);
if (savedInfo.Thumbprint != cert.Thumbprint || savedInfo.Subject != "Тестовый Пользователь")
    throw new Exception("saved info wrong");
if (vault.List(vaultSettings).Count == 0) throw new Exception("saved cert not listed");

// открытая часть доступна без пароля и без закрытого ключа
using (var pub = CertificateVault.PublicPart(savedInfo))
{
    if (pub.HasPrivateKey) throw new Exception("public part must not contain private key");
    if (pub.Thumbprint != cert.Thumbprint) throw new Exception("public part thumbprint mismatch");
}

// загрузка по паролю возвращает рабочий ключ — подписываем и проверяем
using (var loaded = vault.Load(savedInfo, "test-пароль-123"))
{
    if (!loaded.HasPrivateKey) throw new Exception("loaded cert must have private key");
    var sigLoaded = signer.Sign(payload, loaded, detached: true);
    var cmsLoaded = new SignedCms(new ContentInfo(payload), detached: true);
    cmsLoaded.Decode(sigLoaded);
    cmsLoaded.CheckSignature(verifySignatureOnly: true);
}
Console.WriteLine("cert vault: save → load by password → sign+verify: OK");

// неверный пароль — понятная ошибка
try
{
    vault.Load(savedInfo, "wrong");
    throw new Exception("wrong password must fail");
}
catch (InvalidOperationException e) when (e.Message.Contains("пароль"))
{
    Console.WriteLine("cert vault: wrong password → clear error: OK");
}

// установка в системное хранилище: другие программы видят сертификат с ключом
vault.InstallToStore(savedInfo, "test-пароль-123", vaultSettings);
if (!CertificateVault.IsInStore(savedInfo.Thumbprint)) throw new Exception("cert not installed to store");
if (!vaultSettings.InstalledInStore.Contains(savedInfo.Thumbprint)) throw new Exception("install not tracked");
using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
{
    store.Open(OpenFlags.ReadOnly);
    var fromStore = store.Certificates.Find(X509FindType.FindByThumbprint, savedInfo.Thumbprint, false)
        .Cast<X509Certificate2>().First();
    if (!fromStore.HasPrivateKey) throw new Exception("installed cert must keep private key");
    var sigStore = signer.Sign(payload, fromStore, detached: true);   // подпись «как из другой программы»
    var cmsStore = new SignedCms(new ContentInfo(payload), detached: true);
    cmsStore.Decode(sigStore);
    cmsStore.CheckSignature(verifySignatureOnly: true);
    fromStore.Dispose();
}
Console.WriteLine("cert vault: install to system store → visible with key, signs+verifies: OK");

// сертификат УЖЕ в хранилище (например, запись с токена) → установка заменяет
// запись, а не дублирует и не оставляет старую привязку
using (var preStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
{
    preStore.Open(OpenFlags.ReadWrite);
    preStore.Add(new X509Certificate2(cert.RawData)); // «токенная» запись: без ключа
}
vault.InstallToStore(savedInfo, "test-пароль-123", vaultSettings);
using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
{
    store.Open(OpenFlags.ReadOnly);
    var entries = store.Certificates.Find(X509FindType.FindByThumbprint, savedInfo.Thumbprint, false);
    if (entries.Count != 1) throw new Exception($"expected 1 store entry after reinstall, got {entries.Count}");
    if (!entries[0].HasPrivateKey) throw new Exception("reinstalled entry must carry the PFX key");
}
Console.WriteLine("cert vault: install replaces existing store entry (key wins): OK");

// удаление из хранилища: разрешено только для установленных программой
vault.RemoveFromStore(savedInfo.Thumbprint, vaultSettings);
if (CertificateVault.IsInStore(savedInfo.Thumbprint)) throw new Exception("cert must be removed from store");
if (vaultSettings.InstalledInStore.Contains(savedInfo.Thumbprint)) throw new Exception("install record must be removed");
try
{
    vault.RemoveFromStore(certB.Thumbprint, vaultSettings);
    throw new Exception("foreign cert removal must be denied");
}
catch (InvalidOperationException e) when (e.Message.Contains("не был установлен"))
{
    Console.WriteLine("cert vault: remove from store OK; foreign cert removal denied: OK");
}

// удаление: файл затёрт и удалён, запись убрана
var pfxPath = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
    "SignService", "certificates", savedInfo.FileName);
if (!File.Exists(pfxPath)) throw new Exception("pfx file missing before delete");
vault.Delete(savedInfo, vaultSettings);
if (File.Exists(pfxPath)) throw new Exception("pfx file must be deleted");
if (vault.List(vaultSettings).Any(c => c.Thumbprint == savedInfo.Thumbprint))
    throw new Exception("saved record must be removed");
Console.WriteLine("cert vault: delete wipes file and record: OK");

// ===== 14. Сборка криптоконтейнера без подписания =====
var bDir = Path.Combine(tempRoot, "build_container");
Directory.CreateDirectory(bDir);
var bDoc = Path.Combine(bDir, "решение.pdf");
await File.WriteAllBytesAsync(bDoc, payload);
await File.WriteAllBytesAsync(bDoc + ".sig", Merge(sigA, sigB, sigStale)); // рядом: 2 валидные + протухшая

var built = CmsExtractor.BuildContainer(bDoc);
if (built.SignerCount != 2 || built.ExcludedSigners.Count != 1)
    throw new Exception($"build container: {built.SignerCount} signers, excluded {built.ExcludedSigners.Count}");
if (Path.GetFileName(built.OutputPath) != "решение.pdf (контейнер).sig")
    throw new Exception("container name wrong: " + built.OutputPath);
var cmsBuilt = new SignedCms();
cmsBuilt.Decode(await File.ReadAllBytesAsync(built.OutputPath));
cmsBuilt.CheckSignature(verifySignatureOnly: true);
if (!cmsBuilt.ContentInfo.Content.AsSpan().SequenceEqual(payload))
    throw new Exception("container must embed the document");
Console.WriteLine("build container (doc + .sig nearby): attached, doc embedded, 2 signers verify, stale excluded: OK");

// контейнер → извлечение → документ совпадает (обратимость)
var rt = CmsExtractor.ExtractToFiles(built.OutputPath);
if (rt.DocumentPath is null || !(await File.ReadAllBytesAsync(rt.DocumentPath)).SequenceEqual(payload))
    throw new Exception("container extraction roundtrip failed");
Console.WriteLine("build container ↔ extract roundtrip: OK");

// подписи, выбранные вручную (без .sig рядом)
var bDoc2 = Path.Combine(bDir, "письмо.txt");
await File.WriteAllBytesAsync(bDoc2, payload);
var manualSig = Path.Combine(bDir, "письмо-подпись.sig");
await File.WriteAllBytesAsync(manualSig, sigC);
var built2 = CmsExtractor.BuildContainer(bDoc2, new[] { manualSig });
if (built2.SignerCount != 1) throw new Exception("manual-sig container failed");
Console.WriteLine("build container (manual signatures): OK");

// нет подписей вообще — понятная ошибка
var bDoc3 = Path.Combine(bDir, "одинокий.txt");
await File.WriteAllBytesAsync(bDoc3, payload);
try
{
    CmsExtractor.BuildContainer(bDoc3);
    throw new Exception("no signatures must fail");
}
catch (InvalidOperationException e) when (e.Message.Contains(".sig"))
{
    Console.WriteLine("build container without signatures → clear error: OK");
}

// ===== 15. Автообновление: разбор ответа GitHub Releases =====
const string releaseJson = """
    {
      "tag_name": "v9.9.9",
      "html_url": "https://github.com/zaynullinmi/SignService/releases/tag/v9.9.9",
      "assets": [
        { "name": "other.zip", "browser_download_url": "https://example.org/other.zip" },
        { "name": "SignService.exe", "browser_download_url": "https://example.org/SignService.exe" }
      ]
    }
    """;
var upd = UpdateService.ParseLatestRelease(releaseJson, "1.0.0");
if (upd is null || upd.Version != "9.9.9" || upd.ExeDownloadUrl != "https://example.org/SignService.exe"
    || !upd.ReleasePageUrl.Contains("releases/tag"))
    throw new Exception("update parse failed");
if (UpdateService.ParseLatestRelease(releaseJson, "9.9.9") is not null)
    throw new Exception("same version must not offer update");
if (UpdateService.ParseLatestRelease(releaseJson, "10.0.0") is not null)
    throw new Exception("newer local version must not offer update");
if (UpdateService.ParseLatestRelease("""{ "tag_name": "not-a-version" }""", "1.0.0") is not null)
    throw new Exception("bad tag must be ignored");
if (!System.Text.RegularExpressions.Regex.IsMatch(UpdateService.CurrentVersion, @"^\d+\.\d+\.\d+$"))
    throw new Exception("current version format wrong: " + UpdateService.CurrentVersion);
Console.WriteLine($"update check: parse/compare OK (current {UpdateService.CurrentVersion})");

// история версий встроена в сборку
using (var changelog = typeof(DocumentSigner).Assembly.GetManifestResourceStream("SignService.CHANGELOG.md"))
{
    if (changelog is null || changelog.Length < 100) throw new Exception("embedded changelog missing");
}
Console.WriteLine("embedded changelog present: OK");

try { Directory.Delete(tempRoot, true); } catch { }
Console.WriteLine("ALL TESTS PASSED");
return 0;

static bool OpensslAvailable()
{
    try
    {
        using var p = Process.Start(new ProcessStartInfo("openssl", "version")
        { RedirectStandardOutput = true, RedirectStandardError = true })!;
        p.WaitForExit(5000);
        return p.ExitCode == 0;
    }
    catch
    {
        return false;
    }
}

// Локальный RFC 3161-ответчик: HttpListener + `openssl ts -reply`.
sealed class LocalTsa : IDisposable
{
    private readonly HttpListener _listener;
    private readonly string _dir;

    public string Url { get; }

    private LocalTsa(HttpListener listener, string dir, string url)
    {
        _listener = listener;
        _dir = dir;
        Url = url;
    }

    public static async Task<LocalTsa> StartAsync(string dir)
    {
        Directory.CreateDirectory(dir);
        var cnf = Path.Combine(dir, "tsa.cnf");
        await File.WriteAllTextAsync(cnf, """
            [req]
            distinguished_name = dn
            x509_extensions = tsa_ext
            prompt = no
            [dn]
            CN = Test TSA
            O = SignService Test
            [tsa_ext]
            extendedKeyUsage = critical,timeStamping
            keyUsage = digitalSignature
            basicConstraints = CA:false
            [tsa]
            default_tsa = tsa_config1
            [tsa_config1]
            serial = ./serial
            crypto_device = builtin
            signer_cert = ./tsa.crt
            signer_key = ./tsa.key
            default_policy = 1.2.3.4.1
            digests = sha256,sha512
            accuracy = secs:1
            ordering = yes
            tsa_name = yes
            ess_cert_id_chain = no
            signer_digest = sha256
            """);
        Run(dir, $"req -x509 -newkey rsa:2048 -keyout tsa.key -out tsa.crt -days 365 -nodes -config \"{cnf}\"");
        await File.WriteAllTextAsync(Path.Combine(dir, "serial"), "01\n");

        var port = 18100 + Random.Shared.Next(500);
        var url = $"http://127.0.0.1:{port}/";
        var listener = new HttpListener();
        listener.Prefixes.Add(url);
        listener.Start();
        var tsa = new LocalTsa(listener, dir, url);
        _ = Task.Run(tsa.LoopAsync);
        return tsa;
    }

    private async Task LoopAsync()
    {
        while (_listener.IsListening)
        {
            HttpListenerContext ctx;
            try { ctx = await _listener.GetContextAsync(); }
            catch (Exception) { return; }

            var query = Path.Combine(_dir, Guid.NewGuid().ToString("N") + ".tsq");
            var reply = query + ".tsr";
            try
            {
                using (var f = File.Create(query))
                    await ctx.Request.InputStream.CopyToAsync(f);
                Run(_dir, $"ts -reply -queryfile \"{query}\" -out \"{reply}\" -config \"{Path.Combine(_dir, "tsa.cnf")}\"");
                var bytes = await File.ReadAllBytesAsync(reply);
                ctx.Response.ContentType = "application/timestamp-reply";
                ctx.Response.ContentLength64 = bytes.Length;
                await ctx.Response.OutputStream.WriteAsync(bytes);
            }
            catch (Exception)
            {
                ctx.Response.StatusCode = 500;
            }
            finally
            {
                ctx.Response.Close();
                foreach (var f in new[] { query, reply })
                {
                    try { File.Delete(f); } catch { }
                }
            }
        }
    }

    private static void Run(string cwd, string args)
    {
        using var p = Process.Start(new ProcessStartInfo("openssl", args)
        {
            WorkingDirectory = cwd,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        })!;
        p.WaitForExit(30000);
        if (p.ExitCode != 0)
            throw new InvalidOperationException("openssl failed: " + p.StandardError.ReadToEnd());
    }

    public void Dispose()
    {
        try { _listener.Stop(); } catch { }
    }
}
