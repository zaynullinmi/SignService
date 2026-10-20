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

        // Позволяет воспроизвести внешнее изменение после чтения входов, до подписи.
        internal Action? AfterSignatureInputsRead { get; init; }

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

        /// <summary>Ставить ли визуальный штамп о подписании (PDF и Word .docx/.docm).</summary>
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
        /// подписанного документа (как это делает Контур), номер попадает в штамп.
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
    /// к штампованной копии БЕЗ подписи (режим «копия отдельно»). StampWarning —
    /// подпись сохранена, но с копией со штампом что-то не так (не создана или
    /// не все подписанты попали на плашки).
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
        string? BackupPath = null,
        string? StampWarning = null);

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
        // Режим «подписывать копию со штампом»: штамп меняет содержимое документа,
        // поэтому копия создаётся ДО подписания и подписывается именно она.
        // В режиме «копия отдельно» подписывается ОРИГИНАЛ, а штампованная копия
        // (без подписи, со всеми подписантами) создаётся ниже, после подписания.
        var targetPath = filePath;
        var stampAsCopy = options.Stamp && !options.StampSignCopy && DocumentStamper.IsSupported(filePath);
        // Подписанную копию со штампом не трогаем — проверка до подписания, чтобы
        // не получилось «документ подписан, а копию сделать нельзя».
        if (options.Stamp && DocumentStamper.IsSupported(filePath))
            DocumentStamper.ThrowIfCopySigned(filePath);
        var stampOptions = options.StampParameters
            ?? new PdfStamper.StampOptions { WithDate = options.StampWithDate, LogoPath = options.StampLogoPath };
        // Номер МЧД — из проверенного снимка файлов, а не из сохранённых ранее сведений.
        stampOptions = stampOptions with
        {
            PoaNumber = stampOptions.PoaNumber ?? poaPackage?.Info.Number,
        };
        if (options.Stamp && options.StampSignCopy && DocumentStamper.IsSupported(filePath))
        {
            try
            {
                targetPath = DocumentStamper.CreateStampedCopy(
                    filePath, new[] { new PdfStamper.StampSigner(certificate, DateTime.Now, stampOptions.PoaNumber) },
                    stampOptions);
            }
            catch (Exception e)
            {
                var format = DocumentStamper.FormatName(filePath);
                throw new InvalidOperationException(
                    $"Не удалось поставить штамп на {format} ({e.Message}). " +
                    $"Проверьте, что файл — корректный незашифрованный {format}, либо отключите штамп.", e);
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
            ? existingSignaturePath
            : canonicalSignaturePath;

        // Один снимок назначения — и для объединения, и для контроля изменений.
        // Читаем до PIN/TSA, в том числе в режиме замены без объединения.
        var previousBytes = await ReadExistingSignatureAsync(signaturePath, cancellationToken);
        if (options.MergeWithExisting && !string.IsNullOrWhiteSpace(existingSignaturePath) && previousBytes is null)
            throw new IOException("Выбранный файл подписи больше не существует. Повторите поиск подписей.");

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
                inputPaths.Add(existingSignaturePath);
            else
                AddInputPath(canonicalSignaturePath);
        }

        foreach (var path in options.ExtraSignatures)
            AddInputPath(path);

        var inputs = new List<byte[]>();
        foreach (var path in inputPaths)
            inputs.Add(SignatureDiscovery.SamePath(path, signaturePath) && previousBytes is not null
                ? previousBytes : await File.ReadAllBytesAsync(path, cancellationToken));

        var appended = inputPaths.Any(path => string.Equals(
            Path.GetFullPath(path), Path.GetFullPath(signaturePath), StringComparison.OrdinalIgnoreCase));
        var previousSignerCount = appended && previousBytes is not null ? CmsMerger.CountSigners(previousBytes) : 0;
        options.AfterSignatureInputsRead?.Invoke();

        var own = Sign(data, certificate, options.Detached);
        if (options.Timestamp)
        {
            if (string.IsNullOrWhiteSpace(options.TsaUrl))
                throw new InvalidOperationException(
                    "Для подписи со штампом времени укажите адрес службы штампов времени (TSA).");
            var token = await _timestampClient.RequestTokenAsync(
                CmsMerger.GetSignatureValue(own), IsGost(certificate), options.TsaUrl, cancellationToken);
            own = CmsMerger.AddUnsignedAttribute(own, TimestampClient.TimeStampTokenOid, token);
        }
        inputs.Add(own); // своя — последней: при совпадении подписанта она побеждает

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
        var latest = await ReadExistingSignatureAsync(signaturePath, cancellationToken);
        ThrowIfSignatureChanged(previousBytes, latest);
        if (latest is not null)
        {
            var riskyOverwrite = !appended || excluded.Count > 0 || LosesEmbeddedDocument(latest, output);
            if (riskyOverwrite || options.CreateBackup)
                backupPath = SignatureBackup.Create(signaturePath);
        }
        if (poaPackage is not null) PowerOfAttorneyService.CopyPackage(poaPackage, targetPath);
        await AtomicFile.WriteAsync(signaturePath, output, overwrite: previousBytes is not null, cancellationToken,
            beforeCommit: () => ThrowIfSignatureChanged(previousBytes, ReadExistingSignature(signaturePath)));

        // Режим «копия отдельно»: штампованная копия БЕЗ подписи с подписантами
        // итогового .sig — пересоздаётся после каждого подписания. Плашки — только
        // по подписям, которые проверяются по документу; дата у каждого своя,
        // номер МЧД — у того, кто подписывает сейчас. Подпись к этому моменту уже
        // записана, поэтому сбой копии — предупреждение, а не ошибка подписания.
        string? stampedCopyPath = null;
        string? stampWarning = null;
        if (stampAsCopy)
        {
            try
            {
                using var found = DocumentStamper.SignersFromSignatures(new[] { output }, data);
                var signers = found.Signers
                    .Select(s => DocumentStamper.SameCertificate(s.Certificate, certificate)
                        ? s with { PoaNumber = stampOptions.PoaNumber }
                        : s)
                    .ToList();
                if (!signers.Any(s => DocumentStamper.SameCertificate(s.Certificate, certificate)))
                    signers.Add(new PdfStamper.StampSigner(certificate, DateTime.Now, stampOptions.PoaNumber));
                stampedCopyPath = DocumentStamper.CreateStampedCopy(filePath, signers, stampOptions);
                if (found.Skipped.Count > 0)
                    stampWarning = "в копии со штампом нет плашек для подписей, которые не удалось проверить по документу: "
                        + string.Join("; ", found.Skipped);
            }
            catch (Exception e)
            {
                stampWarning = $"подпись сохранена, но копию со штампом создать не удалось: {e.Message}";
            }
        }

        return new SignFileResult(
            targetPath, signaturePath, signerCount, excluded, unverified, stampedCopyPath,
            previousSignerCount, appended, backupPath, stampWarning);
    }

    /// <summary>
    /// Отказ от записи, если файл подписи сменился после того, как его прочитали
    /// для объединения. Иначе более новая чужая подпись была бы затёрта нашей копией.
    /// </summary>
    internal static void ThrowIfSignatureChanged(byte[]? snapshot, byte[]? latest)
    {
        if (snapshot is null ? latest is not null : latest is null || !snapshot.AsSpan().SequenceEqual(latest))
            throw new IOException(
                "Файл подписи изменился во время подписания. Подпись не сохранена; повторите операцию.");
    }

    private static async Task<byte[]?> ReadExistingSignatureAsync(string path, CancellationToken cancellationToken)
    {
        try { return await File.ReadAllBytesAsync(path, cancellationToken); }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
    }

    private static byte[]? ReadExistingSignature(string path)
    {
        try { return File.ReadAllBytes(path); }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
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
