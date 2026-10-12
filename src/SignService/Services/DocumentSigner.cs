using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace SignService.Services;

/// <summary>
/// Подписание документов ЭЦП в формате CMS/PKCS#7 (схема портирована из ReportGGE).
/// На Windows подпись создаётся нативным CryptSignMessage (см. <see cref="NativeSign"/>):
/// .NET SignedCms не умеет ГОСТ, а CryptoAPI отдаёт операцию криптопровайдеру
/// сертификата (для ГОСТ — КриптоПро CSP, с диалогом PIN-кода при необходимости).
/// Вне Windows — запасной путь через SignedCms (RSA/ECDSA).
/// </summary>
public class DocumentSigner
{
    /// <summary>Параметры подписания файла.</summary>
    public sealed record SignOptions
    {
        /// <summary>Откреплённая (true) или прикреплённая подпись.</summary>
        public bool Detached { get; init; } = true;

        /// <summary>Объединять ли с уже существующим файлом .sig (соподписание).</summary>
        public bool MergeWithExisting { get; init; }

        /// <summary>
        /// Сохранять .bak перед любой перезаписью существующего .sig, в том числе
        /// при обычном дописывании. Без этого копия создаётся только в рискованных
        /// случаях: замена без объединения, исключение подписантов или потеря
        /// документа, вложенного в прикреплённую подпись.
        /// </summary>
        public bool CreateBackup { get; init; }

        /// <summary>
        /// Вызывается после подготовки новой подписи и до её записи.
        /// Нужен тестам, чтобы подменить файл подписи в этот промежуток.
        /// </summary>
        internal Action? BeforePublish { get; init; }

        /// <summary>Пути к .sig других подписантов для объединения.</summary>
        public IReadOnlyList<string> ExtraSignatures { get; init; } = Array.Empty<string>();

        /// <summary>
        /// Существующий файл подписи, в который добавляется своя. Если задан,
        /// результат записывается в него (а не в «документ.sig»): так сохраняется
        /// файл с нестандартным именем, найденный по хешу документа.
        /// </summary>
        public string? ExistingSignaturePath { get; init; }

        /// <summary>Добавлять ли штамп времени TSA (CAdES-T) в подпись.</summary>
        public bool Timestamp { get; init; }

        /// <summary>Адрес службы штампов времени (RFC 3161).</summary>
        public string? TsaUrl { get; init; }

        /// <summary>Ставить ли визуальный штамп о подписании на PDF-документ.</summary>
        public bool Stamp { get; init; }

        /// <summary>
        /// true — подписывается копия со штампом (штамп до подписи; подпись
        /// действует именно на штампованный файл). false (по умолчанию) —
        /// подписывается ОРИГИНАЛ, а копия со штампом всех подписантов создаётся
        /// отдельно БЕЗ подписи: безопасно при соподписании — штамп не ломает
        /// подписи других подписантов.
        /// </summary>
        public bool StampSignCopy { get; init; }

        /// <summary>Включать ли дату подписания в визуальный штамп.</summary>
        public bool StampWithDate { get; init; } = true;

        /// <summary>Путь к картинке логотипа для штампа (PNG/JPEG) или null.</summary>
        public string? StampLogoPath { get; init; }

        /// <summary>
        /// Полные параметры штампа (страницы и т.д.); если null — собираются
        /// из StampWithDate/StampLogoPath (последняя страница).
        /// </summary>
        public PdfStamper.StampOptions? StampParameters { get; init; }

        /// <summary>
        /// Доверенность МЧД: файлы XML и подписи руководителя копируются в каталог
        /// подписанного документа (как это делает Контур), номер попадает в PDF-штамп.
        /// </summary>
        public PowerOfAttorneyService.PoaInfo? PowerOfAttorney { get; init; }

        public VerificationOptions? PoaVerificationOptions { get; init; }

        /// <summary>
        /// МЧД, уже проверенная для этого сертификата (один раз на пакет файлов):
        /// повторная полная проверка не выполняется, копируется именно этот снимок.
        /// </summary>
        internal PowerOfAttorneyService.PoaPackage? PreparedPowerOfAttorney { get; init; }
    }

    /// <summary>
    /// Результат подписания файла: подписанный документ (в режиме «подписывать
    /// копию со штампом» — путь к ней), путь к .sig, число подписантов,
    /// исключённые при объединении подписи, не проверенные подписи и путь
    /// к штампованной копии БЕЗ подписи (режим «копия отдельно»).
    /// </summary>
    public readonly record struct SignFileResult(
        string SignedDocumentPath,
        string SignaturePath,
        int SignerCount,
        IReadOnlyList<string> ExcludedSigners,
        IReadOnlyList<string> UnverifiedSigners,
        string? StampedCopyPath = null,
        int PreviousSignerCount = 0,
        bool AppendedToExisting = false,
        string? BackupPath = null);

    private readonly TimestampClient _timestampClient = new();

    /// <summary>
    /// Подписывает файл и сохраняет подпись рядом с ним в файле "&lt;имя&gt;.sig".
    /// При необходимости объединяет свою подпись с уже существующей .sig и/или
    /// с приложенными подписями других лиц (соподписание) — итоговый файл содержит
    /// всех подписантов.
    /// </summary>
    /// <param name="filePath">Путь к подписываемому файлу.</param>
    /// <param name="certificate">Сертификат с закрытым ключом.</param>
    /// <param name="detached">
    /// true — откреплённая подпись (файл .sig содержит только подпись, как требуют
    /// госпорталы и большинство контрагентов); false — прикреплённая (документ внутри .sig).
    /// </param>
    /// <param name="mergeWithExisting">Объединять ли с уже существующим файлом "&lt;имя&gt;.sig".</param>
    /// <param name="extraSignatures">Пути к .sig других подписантов для объединения.</param>
    public Task<SignFileResult> SignFileAsync(
        string filePath,
        X509Certificate2 certificate,
        bool detached = true,
        bool mergeWithExisting = false,
        IReadOnlyList<string>? extraSignatures = null,
        CancellationToken cancellationToken = default)
        => SignFileAsync(filePath, certificate, new SignOptions
        {
            Detached = detached,
            MergeWithExisting = mergeWithExisting,
            ExtraSignatures = extraSignatures ?? Array.Empty<string>(),
        }, cancellationToken);

    public async Task<SignFileResult> SignFileAsync(
        string filePath,
        X509Certificate2 certificate,
        SignOptions options,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var poaPackage = options.PreparedPowerOfAttorney ?? (options.PowerOfAttorney is { } selectedPoa
            ? PowerOfAttorneyService.Prepare(selectedPoa, certificate, options.PoaVerificationOptions) : null);
        if (poaPackage?.Check.State == PowerOfAttorneyService.CheckState.Error)
            throw new InvalidOperationException(poaPackage.Check.Message);
        if (poaPackage is not null) PowerOfAttorneyService.CheckCopyTargets(poaPackage, filePath);
        // Режим «подписывать копию со штампом»: штамп меняет содержимое PDF,
        // поэтому копия создаётся ДО подписания и подписывается именно она.
        // В режиме «копия отдельно» подписывается ОРИГИНАЛ, а штампованная копия
        // (без подписи, со всеми подписантами) создаётся ниже, после подписания.
        var targetPath = filePath;
        var stampAsCopy = options.Stamp && !options.StampSignCopy && PdfStamper.IsPdf(filePath);
        var stampOptions = options.StampParameters
            ?? new PdfStamper.StampOptions { WithDate = options.StampWithDate, LogoPath = options.StampLogoPath };
        // Номер МЧД — из проверенного снимка файлов, а не из сохранённых ранее сведений.
        stampOptions = stampOptions with
        {
            PoaNumber = stampOptions.PoaNumber ?? poaPackage?.Info.Number,
        };
        if (options.Stamp && options.StampSignCopy && PdfStamper.IsPdf(filePath))
        {
            try
            {
                targetPath = PdfStamper.CreateStampedCopy(
                    filePath, new[] { certificate }, stampOptions, DateTime.Now);
            }
            catch (Exception e)
            {
                throw new InvalidOperationException(
                    $"Не удалось поставить штамп на PDF ({e.Message}). " +
                    "Проверьте, что файл — корректный незашифрованный PDF, либо отключите штамп.", e);
            }
        }

        var data = await File.ReadAllBytesAsync(targetPath, cancellationToken);
        var canonicalSignaturePath = targetPath + ".sig";
        // Найденный файл подписи относится к оригиналу; копия со штампом — другой документ.
        var existingSignaturePath = string.Equals(targetPath, filePath, StringComparison.Ordinal)
            ? options.ExistingSignaturePath
            : null;
        var signaturePath = options.MergeWithExisting
            && !string.IsNullOrWhiteSpace(existingSignaturePath)
            && File.Exists(existingSignaturePath)
            ? existingSignaturePath
            : canonicalSignaturePath;

        // Свою подпись создаём ДО чтения объединяемых файлов, чтобы ошибка
        // подписания не оставила .sig наполовину обработанным.
        var own = Sign(data, certificate, options.Detached);

        // Штамп времени TSA (CAdES-T) — неподписанный атрибут на значение подписи.
        if (options.Timestamp)
        {
            if (string.IsNullOrWhiteSpace(options.TsaUrl))
                throw new InvalidOperationException(
                    "Для подписи со штампом времени укажите адрес службы штампов времени (TSA).");

            var token = await _timestampClient.RequestTokenAsync(
                CmsMerger.GetSignatureValue(own), IsGost(certificate), options.TsaUrl, cancellationToken);
            own = CmsMerger.AddUnsignedAttribute(own, TimestampClient.TimeStampTokenOid, token);
        }

        var inputPaths = new List<string>();
        void AddInputPath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return;
            if (inputPaths.Any(existing => string.Equals(
                    Path.GetFullPath(existing), Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase)))
                return;
            inputPaths.Add(path);
        }

        if (options.MergeWithExisting)
        {
            if (!string.IsNullOrWhiteSpace(existingSignaturePath))
                AddInputPath(existingSignaturePath);
            else
                AddInputPath(canonicalSignaturePath);
        }

        foreach (var path in options.ExtraSignatures)
            AddInputPath(path);

        var inputs = new List<byte[]>();
        foreach (var path in inputPaths)
            inputs.Add(await File.ReadAllBytesAsync(path, cancellationToken));
        inputs.Add(own); // своя — последней: при совпадении подписанта она побеждает

        var appended = inputPaths.Any(path => string.Equals(
            Path.GetFullPath(path), Path.GetFullPath(signaturePath), StringComparison.OrdinalIgnoreCase));
        // Снимок того, что вошло в объединение. Перед записью файл читается ещё раз:
        // за время PIN-кода или пакетного подписания его могли обновить.
        byte[]? previousBytes = null;
        var previousSignerCount = 0;
        if (appended)
        {
            previousBytes = await File.ReadAllBytesAsync(signaturePath, cancellationToken);
            previousSignerCount = CmsMerger.CountSigners(previousBytes);
        }

        int signerCount;
        IReadOnlyList<string> excluded;
        IReadOnlyList<string> unverified;
        byte[] output;
        if (inputs.Count == 1)
        {
            output = own;
            signerCount = 1;
            excluded = Array.Empty<string>();
            unverified = Array.Empty<string>();
        }
        else
        {
            // Объединение с проверкой: подписи под другим файлом или прежней версией
            // документа исключаются — иначе портал отклонит весь контейнер.
            var merged = CmsMerger.MergeForDocument(inputs, data, attach: !options.Detached);
            output = merged.Signature;
            signerCount = merged.SignerCount;
            excluded = merged.ExcludedSigners;
            unverified = merged.UnverifiedSigners;
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (!(await File.ReadAllBytesAsync(targetPath, cancellationToken)).AsSpan().SequenceEqual(data))
            throw new IOException("Документ изменился во время подписания. Подпись не сохранена; повторите операцию.");
        options.BeforePublish?.Invoke();
        // Рискованные случаи — всегда: файл заменяется без объединения, из него
        // исключаются подписанты или пропадает документ внутри прикреплённой подписи.
        // Галочка добавляет копию и при обычном дописывании. Если файл успели
        // изменить после чтения — не пишем ничего, в том числе файлы МЧД.
        string? backupPath = null;
        if (File.Exists(signaturePath))
        {
            var latest = await File.ReadAllBytesAsync(signaturePath, cancellationToken);
            ThrowIfSignatureChanged(previousBytes, latest);
            var riskyOverwrite = !appended || excluded.Count > 0 || LosesEmbeddedDocument(latest, output);
            if (riskyOverwrite || options.CreateBackup)
                backupPath = SignatureBackup.Create(signaturePath);
        }
        if (poaPackage is not null) PowerOfAttorneyService.CopyPackage(poaPackage, targetPath);
        await AtomicFile.WriteAsync(signaturePath, output, overwrite: true, cancellationToken);

        // Режим «копия отдельно»: штампованная копия БЕЗ подписи, со всеми
        // подписантами итогового .sig — пересоздаётся после каждого подписания.
        string? stampedCopyPath = null;
        if (stampAsCopy)
        {
            try
            {
                var signerCerts = CmsMerger.GetSignerCertificates(
                    await File.ReadAllBytesAsync(signaturePath, cancellationToken));
                var stampCerts = signerCerts.Count > 0
                    ? signerCerts
                    : new List<X509Certificate2> { certificate };
                stampedCopyPath = PdfStamper.CreateStampedCopy(
                    filePath, stampCerts, stampOptions, DateTime.Now);
                foreach (var c in signerCerts)
                    c.Dispose();
            }
            catch (Exception e)
            {
                throw new InvalidOperationException(
                    $"Документ подписан, но не удалось создать копию со штампом ({e.Message}).", e);
            }
        }

        return new SignFileResult(
            targetPath, signaturePath, signerCount, excluded, unverified, stampedCopyPath,
            previousSignerCount, appended, backupPath);
    }

    /// <summary>
    /// Отказ от записи, если файл подписи сменился после того, как его прочитали
    /// для объединения. Иначе более новая чужая подпись была бы затёрта нашей копией.
    /// </summary>
    internal static void ThrowIfSignatureChanged(byte[]? snapshot, byte[] latest)
    {
        if (snapshot is not null && !snapshot.AsSpan().SequenceEqual(latest))
            throw new IOException(
                "Файл подписи изменился во время подписания. Подпись не сохранена; повторите операцию.");
    }

    /// <summary>
    /// true, если в существующей прикреплённой подписи есть документ, а в новой
    /// записи его не будет или он станет другим. Сами значения подписей при этом
    /// могут сохраниться — пропадает копия документа внутри .sig.
    /// </summary>
    internal static bool LosesEmbeddedDocument(byte[] existing, byte[] output)
    {
        byte[]? embedded;
        try { embedded = CmsMerger.ExtractContent(existing); }
        catch (Exception) { return true; }
        if (embedded is null)
            return false;
        try
        {
            var kept = CmsMerger.ExtractContent(output);
            return kept is null || !kept.AsSpan().SequenceEqual(embedded);
        }
        catch (Exception)
        {
            return true;
        }
    }

    /// <summary>
    /// Формирует CMS/PKCS#7 подпись для массива байтов.
    /// </summary>
    public byte[] Sign(byte[] data, X509Certificate2 certificate, bool detached = true)
    {
        if (data is null || data.Length == 0)
            throw new ArgumentException("Нет данных для подписания: файл пуст.", nameof(data));
        if (!certificate.HasPrivateKey)
            throw new InvalidOperationException(
                $"У сертификата «{CertificateProvider.GetSubjectName(certificate)}» нет закрытого ключа.");

        if (OperatingSystem.IsWindows())
            return SignNative(data, certificate, detached);

        return SignManaged(data, certificate, detached);
    }

    /// <summary>
    /// OID алгоритма хеширования по типу ключа сертификата (как в ReportGGE):
    /// для ГОСТ-ключей — соответствующий ГОСТ Р 34.11, иначе SHA-256.
    /// </summary>
    public static string HashOidFor(X509Certificate2 certificate) =>
        certificate.PublicKey.Oid?.Value switch
        {
            "1.2.643.7.1.1.1.1" => "1.2.643.7.1.1.2.2", // ГОСТ Р 34.10-2012 (256) → 34.11-2012 (256)
            "1.2.643.7.1.1.1.2" => "1.2.643.7.1.1.2.3", // ГОСТ Р 34.10-2012 (512) → 34.11-2012 (512)
            "1.2.643.2.2.19"    => "1.2.643.2.2.9",     // ГОСТ Р 34.10-2001 → 34.11-94
            _ => "2.16.840.1.101.3.4.2.1",              // SHA-256 (RSA/ECDSA)
        };

    /// <summary>Является ли сертификат ГОСТ-сертификатом (ключ ГОСТ Р 34.10).</summary>
    public static bool IsGost(X509Certificate2 certificate) =>
        (certificate.PublicKey.Oid?.Value ?? "").StartsWith("1.2.643.", StringComparison.Ordinal);

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static byte[] SignNative(byte[] data, X509Certificate2 certificate, bool detached)
    {
        // Усиленный формат (CAdES-BES): подписанные атрибуты — время подписания
        // и signing-certificate-v2 (защита от подмены сертификата). content-type
        // и message-digest CryptoAPI добавит сам.
        var attrs = new[]
        {
            new NativeSign.AuthAttribute(
                CadesAttributes.SigningTimeOid,
                CadesAttributes.BuildSigningTime(DateTimeOffset.UtcNow)),
            new NativeSign.AuthAttribute(
                CadesAttributes.SigningCertificateV2Oid,
                CadesAttributes.BuildSigningCertificateV2(certificate)),
        };

        // Вкладываем в подпись всю цепочку (лист + УЦ + корень), как это делает
        // портал в ReportGGE — чтобы подпись проверялась офлайн.
        var embed = BuildChain(certificate);
        try
        {
            return NativeSign.Sign(data, certificate, embed, HashOidFor(certificate), detached, attrs);
        }
        finally
        {
            foreach (var c in embed)
                if (!ReferenceEquals(c, certificate))
                    c.Dispose(); // лист принадлежит вызывающему — не трогаем
        }
    }

    // Запасной путь для Linux/macOS: штатный SignedCms (ГОСТ не поддерживает).
    private static byte[] SignManaged(byte[] data, X509Certificate2 certificate, bool detached)
    {
        if (IsGost(certificate))
            throw new PlatformNotSupportedException(
                "Подписание ГОСТ-сертификатом доступно только на Windows с установленным КриптоПро CSP.");

        var signedCms = new SignedCms(new ContentInfo(data), detached);
        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate)
        {
            IncludeOption = X509IncludeOption.ExcludeRoot,
        };
        // Те же атрибуты CAdES-BES, что и в нативном пути.
        signer.SignedAttributes.Add(new Pkcs9SigningTime(DateTime.Now));
        signer.SignedAttributes.Add(new Pkcs9AttributeObject(
            CadesAttributes.SigningCertificateV2Oid,
            CadesAttributes.BuildSigningCertificateV2(certificate)));
        signedCms.ComputeSignature(signer, silent: false);
        return signedCms.Encode();
    }

    // DER-байты цепочки по отпечатку сертификата. X509Chain.Build — дорогой вызов,
    // а цепочка одного сертификата неизменна; кешируем, чтобы пакетное подписание
    // не строило её заново на каждый файл (как в ReportGGE).
    private static readonly ConcurrentDictionary<string, byte[][]> ChainBlobs = new();

    /// <summary>
    /// Цепочка для вложения в подпись: сам сертификат + найденные сертификаты УЦ.
    /// Если построить цепочку не удалось (нет УЦ в хранилищах) — вернётся только лист.
    /// Все элементы, кроме листа, создаются заново и подлежат Dispose вызывающим.
    /// </summary>
    private static List<X509Certificate2> BuildChain(X509Certificate2 certificate)
    {
        var blobs = ChainBlobs.GetOrAdd(certificate.Thumbprint ?? "", _ => BuildChainBlobs(certificate));
        var list = new List<X509Certificate2> { certificate };
        foreach (var blob in blobs)
        {
            try
            {
                var c = new X509Certificate2(blob);
                if (list.All(x => x.Thumbprint != c.Thumbprint))
                    list.Add(c);
                else
                    c.Dispose();
            }
            catch
            {
                // повреждённый элемент цепочки просто пропускаем
            }
        }

        return list;
    }

    private static byte[][] BuildChainBlobs(X509Certificate2 certificate)
    {
        var blobs = new List<byte[]>();
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            // Нужна сама цепочка, а не вердикт о валидности.
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
            chain.Build(certificate);
            foreach (var element in chain.ChainElements)
                blobs.Add(element.Certificate.RawData);
        }
        catch
        {
            // не построилась — подпишем с одним листовым сертификатом
        }

        return blobs.ToArray();
    }

    /// <summary>
    /// Проверяет откреплённую подпись для файла (только криптографическую
    /// корректность, без проверки доверия цепочки). ГОСТ поддерживается
    /// управляемой библиотекой на любой платформе без криптопровайдера.
    /// </summary>
    public bool VerifyDetached(byte[] data, byte[] signature)
    {
        return SignatureVerifier.Verify(signature, data, VerificationOptions.CryptographyOnly).CryptographicallyValid;
    }
}
