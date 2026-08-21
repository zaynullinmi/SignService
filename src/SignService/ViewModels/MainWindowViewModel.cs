using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SignService.Services;

namespace SignService.ViewModels;

public partial class MainWindowViewModel : ObservableObject
{
    private readonly CertificateProvider _certificateProvider;
    private readonly DocumentSigner _documentSigner;
    private readonly CertificateVault _vault = new();
    private readonly AppSettings _settings;
    private bool _initializing;

    public MainWindowViewModel(CertificateProvider certificateProvider, DocumentSigner documentSigner)
    {
        _certificateProvider = certificateProvider;
        _documentSigner = documentSigner;
        _settings = AppSettings.Load();

        _initializing = true;
        IsDetached = _settings.DetachedSignature;
        MergeWithExisting = _settings.MergeWithExisting;
        UseTimestamp = _settings.UseTimestamp;
        TsaUrl = _settings.TsaUrl;
        UseStamp = _settings.UseStamp;
        StampWithDate = _settings.StampWithDate;
        StampLogoPath = _settings.StampLogoPath;
        _initializing = false;

        Files.CollectionChanged += (_, _) => SignAllCommand.NotifyCanExecuteChanged();
        RefreshCertificates();
    }

    public ObservableCollection<CertificateItem> Certificates { get; } = new();

    public ObservableCollection<SignFileItem> Files { get; } = new();

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SignAllCommand))]
    [NotifyCanExecuteChangedFor(nameof(SaveCertificateCommand))]
    [NotifyCanExecuteChangedFor(nameof(DeleteCertificateCommand))]
    [NotifyCanExecuteChangedFor(nameof(InstallCertificateCommand))]
    [NotifyCanExecuteChangedFor(nameof(RemoveFromStoreCommand))]
    [NotifyCanExecuteChangedFor(nameof(StampOnlyCommand))]
    private CertificateItem? _selectedCertificate;

    /// <summary>Откреплённая подпись (.sig отдельно от документа) — режим по умолчанию.</summary>
    [ObservableProperty]
    private bool _isDetached = true;

    /// <summary>
    /// Объединять свою подпись с уже существующим файлом .sig рядом с документом
    /// (соподписание) вместо его замены.
    /// </summary>
    [ObservableProperty]
    private bool _mergeWithExisting = true;

    [ObservableProperty]
    private bool _includeExpiredCertificates;

    /// <summary>Подпись со штампом времени TSA (CAdES-T) вместо обычной (CAdES-BES).</summary>
    [ObservableProperty]
    private bool _useTimestamp;

    [ObservableProperty]
    private string _tsaUrl = "";

    /// <summary>Ставить визуальный штамп о подписании на PDF-документы.</summary>
    [ObservableProperty]
    private bool _useStamp;

    [ObservableProperty]
    private bool _stampWithDate = true;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StampLogoDisplay))]
    private string? _stampLogoPath;

    public string StampLogoDisplay => StampLogoPath is null
        ? "лого не выбрано"
        : System.IO.Path.GetFileName(StampLogoPath);

    /// <summary>Запрос диалога выбора картинки логотипа для штампа.</summary>
    public event EventHandler? PickLogoRequested;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SignAllCommand))]
    [NotifyCanExecuteChangedFor(nameof(BrowseCommand))]
    [NotifyCanExecuteChangedFor(nameof(ClearCommand))]
    private bool _isBusy;

    [ObservableProperty]
    private string _statusText = "Перетащите файлы в окно или добавьте их через «Обзор…»";

    /// <summary>Текст окна лога: все операции с отметкой времени.</summary>
    [ObservableProperty]
    private string _logText = "";

    /// <summary>Показывать ли панель лога.</summary>
    [ObservableProperty]
    private bool _isLogVisible;

    // Каждая смена статуса попадает и в лог — плюс подробные строки по файлам.
    partial void OnStatusTextChanged(string value) => Log(value);

    private void Log(string message)
    {
        if (string.IsNullOrWhiteSpace(message))
            return;
        LogText += $"[{DateTime.Now:HH:mm:ss}] {message}\n";
    }

    [RelayCommand]
    private void ToggleLog() => IsLogVisible = !IsLogVisible;

    [RelayCommand]
    private void ClearLog() => LogText = "";

    /// <summary>
    /// Запрос диалога выбора файлов; обрабатывается в MainWindow,
    /// т.к. StorageProvider доступен только на уровне окна.
    /// </summary>
    public event EventHandler? BrowseRequested;

    /// <summary>Запрос диалога выбора .sig других лиц для объединения с подписью файла.</summary>
    public event EventHandler<SignFileItem>? AttachSignaturesRequested;

    /// <summary>Запрос диалога выбора контейнеров для извлечения.</summary>
    public event EventHandler? ExtractRequested;

    /// <summary>Запрос диалога выбора подписей для объединения без подписания.</summary>
    public event EventHandler? MergeFilesRequested;

    /// <summary>Запрос диалога выбора PDF для штампа без подписания.</summary>
    public event EventHandler? StampOnlyRequested;

    /// <summary>Запрос диалога выбора документа для сборки криптоконтейнера.</summary>
    public event EventHandler? BuildContainerRequested;

    /// <summary>
    /// Запрос пароля у пользователя (заголовок, сообщение, предупреждение или null,
    /// требуется ли повторный ввод). Возвращает пароль или null при отмене.
    /// Реализация — в MainWindow (модальный диалог).
    /// </summary>
    public Func<string, string, string?, bool, Task<string?>>? RequestPasswordAsync { get; set; }

    /// <summary>Запрос подтверждения «Да/Нет» (заголовок, сообщение).</summary>
    public Func<string, string, Task<bool>>? RequestConfirmAsync { get; set; }

    partial void OnIncludeExpiredCertificatesChanged(bool value) => RefreshCertificates();

    // Как в ReportGGE: выбор запоминается, следующий запуск подписывает тем же
    // сертификатом без повторного выбора.
    partial void OnSelectedCertificateChanged(CertificateItem? value)
    {
        if (_initializing || value is null)
            return;
        _settings.SignCertThumbprint = value.Thumbprint;
        _settings.Save();
    }

    partial void OnIsDetachedChanged(bool value)
    {
        if (_initializing)
            return;
        _settings.DetachedSignature = value;
        _settings.Save();
    }

    partial void OnMergeWithExistingChanged(bool value)
    {
        if (_initializing)
            return;
        _settings.MergeWithExisting = value;
        _settings.Save();
    }

    partial void OnUseTimestampChanged(bool value)
    {
        if (_initializing) return;
        _settings.UseTimestamp = value;
        _settings.Save();
    }

    partial void OnTsaUrlChanged(string value)
    {
        if (_initializing) return;
        _settings.TsaUrl = value;
        _settings.Save();
    }

    partial void OnUseStampChanged(bool value)
    {
        if (_initializing) return;
        _settings.UseStamp = value;
        _settings.Save();
    }

    partial void OnStampWithDateChanged(bool value)
    {
        if (_initializing) return;
        _settings.StampWithDate = value;
        _settings.Save();
    }

    partial void OnStampLogoPathChanged(string? value)
    {
        if (_initializing) return;
        _settings.StampLogoPath = value;
        _settings.Save();
    }

    [RelayCommand]
    private void PickLogo() => PickLogoRequested?.Invoke(this, EventArgs.Empty);

    [RelayCommand]
    private void ClearLogo() => StampLogoPath = null;

    [RelayCommand]
    private void RefreshCertificates()
    {
        // Предпочитаем текущий выбор, затем сохранённый в настройках отпечаток.
        var previous = SelectedCertificate?.Thumbprint ?? _settings.SignCertThumbprint;
        Certificates.Clear();

        try
        {
            foreach (var certificate in _certificateProvider.GetSigningCertificates(IncludeExpiredCertificates))
                Certificates.Add(new CertificateItem(certificate));
        }
        catch (Exception ex)
        {
            StatusText = $"Не удалось прочитать хранилище сертификатов: {ex.Message}";
        }

        // Сохранённые на компьютер (PFX): если такой же сертификат виден и в системном
        // хранилище (токен подключён), показываем только вариант из хранилища.
        foreach (var saved in _vault.List(_settings))
        {
            if (Certificates.Any(c => string.Equals(c.Thumbprint, saved.Thumbprint, StringComparison.OrdinalIgnoreCase)))
                continue;

            try
            {
                var item = new CertificateItem(saved);
                if (IncludeExpiredCertificates || !item.IsExpired)
                    Certificates.Add(item);
            }
            catch (Exception)
            {
                // повреждённая запись — пропускаем
            }
        }

        SelectedCertificate =
            Certificates.FirstOrDefault(c => c.Thumbprint == previous) ?? Certificates.FirstOrDefault();

        StatusText = Certificates.Count == 0
            ? "В хранилище не найдено сертификатов с закрытым ключом"
            : $"Найдено сертификатов: {Certificates.Count}";
    }

    private bool CanSaveCertificate() =>
        !IsBusy && SelectedCertificate is { IsSaved: false };

    /// <summary>
    /// Сохраняет выбранный сертификат с закрытым ключом на компьютер (PFX с паролем),
    /// чтобы подписывать без подключённого ключа ЭЦП. Обязательно предупреждает.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanSaveCertificate))]
    private async Task SaveCertificateAsync()
    {
        if (SelectedCertificate is not { IsSaved: false } item || RequestPasswordAsync is null)
            return;

        var password = await RequestPasswordAsync(
            "Сохранение сертификата на компьютер",
            $"Сертификат «{item.Subject}» будет сохранён на этот компьютер в файле-контейнере, "
            + "защищённом паролем. После этого подписывать можно будет без подключённого ключа ЭЦП.",
            "⚠ ВНИМАНИЕ: закрытый ключ окажется в файле на диске и будет защищён ТОЛЬКО этим паролем. "
            + "Любой, кто получит файл и пароль, сможет подписывать документы от вашего имени. "
            + "Это менее безопасно, чем хранение ключа на токене. Используйте длинный пароль "
            + "и удалите сертификат с компьютера, когда он перестанет быть нужен.",
            true);
        if (password is null)
            return;

        try
        {
            await Task.Run(() => _vault.Save(item.Certificate, password, _settings));
            RefreshCertificates();
            StatusText = $"Сертификат «{item.Subject}» сохранён на компьютер. "
                + "Теперь подписание доступно без ключа ЭЦП (потребуется пароль).";
        }
        catch (Exception ex)
        {
            StatusText = "Сохранение сертификата: " + ex.Message;
        }
    }

    // Удалять можно и когда токен подключён (в списке — вариант из хранилища,
    // но на диске есть сохранённая копия с тем же отпечатком).
    private bool CanDeleteCertificate() =>
        !IsBusy && SelectedCertificate is { } sel
            && _settings.SavedCertificates.Any(c =>
                string.Equals(c.Thumbprint, sel.Thumbprint, StringComparison.OrdinalIgnoreCase));

    /// <summary>Удаляет сохранённую на компьютере копию сертификата (PFX затирается).</summary>
    [RelayCommand(CanExecute = nameof(CanDeleteCertificate))]
    private async Task DeleteCertificateAsync()
    {
        var item = SelectedCertificate;
        if (item is null || RequestConfirmAsync is null)
            return;

        var saved = _settings.SavedCertificates.FirstOrDefault(c =>
            string.Equals(c.Thumbprint, item.Thumbprint, StringComparison.OrdinalIgnoreCase));
        if (saved is null)
            return;

        var confirmed = await RequestConfirmAsync(
            "Удаление сертификата с компьютера",
            $"Удалить сохранённую на компьютере копию сертификата «{saved.Subject}»?\n\n"
            + "Файл с закрытым ключом будет затёрт и удалён. Подписание этим сертификатом "
            + "снова потребует подключённого ключа ЭЦП. Сам сертификат в системном "
            + "хранилище и на токене не затрагивается.");
        if (!confirmed)
            return;

        try
        {
            await Task.Run(() => _vault.Delete(saved, _settings));
            RefreshCertificates();
            StatusText = $"Сохранённая копия сертификата «{saved.Subject}» удалена с компьютера.";
        }
        catch (Exception ex)
        {
            StatusText = "Удаление сертификата: " + ex.Message;
        }
    }

    private bool CanInstallCertificate() =>
        !IsBusy && SelectedCertificate is { IsSaved: true };

    /// <summary>
    /// Устанавливает сохранённый на ПК сертификат в системное хранилище Windows —
    /// чтобы им можно было подписывать и в ДРУГИХ программах (КриптоАРМ, браузер и т.д.).
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanInstallCertificate))]
    private async Task InstallCertificateAsync()
    {
        if (SelectedCertificate is not { Saved: { } saved } item || RequestPasswordAsync is null)
            return;

        var password = await RequestPasswordAsync(
            "Установка сертификата в хранилище Windows",
            $"Сертификат «{item.Subject}» будет установлен в системное хранилище "
            + "(«Текущий пользователь → Личное»). Введите пароль, заданный при сохранении.",
            "⚠ ВНИМАНИЕ: после установки закрытый ключ станет доступен ВСЕМ программам, "
            + "работающим под вашей учётной записью Windows (браузеры, КриптоАРМ и др.), — "
            + "без ввода пароля этой программы. Ключ будет защищён средствами Windows. "
            + "Устанавливайте только на личном компьютере и удалите из хранилища, "
            + "когда перестанет быть нужен.",
            false);
        if (password is null)
            return;

        try
        {
            await Task.Run(() => _vault.InstallToStore(saved, password, _settings));
            RefreshCertificates();
            StatusText = $"Сертификат «{item.Subject}» установлен в хранилище Windows — "
                + "теперь им можно подписывать и в других программах.";
        }
        catch (Exception ex)
        {
            StatusText = "Установка в хранилище: " + ex.Message;
        }
    }

    // Удалять из хранилища разрешаем только то, что программа сама установила.
    private bool CanRemoveFromStore() =>
        !IsBusy && SelectedCertificate is { } sel
            && _settings.InstalledInStore.Contains(sel.Thumbprint, StringComparer.OrdinalIgnoreCase);

    /// <summary>Удаляет из системного хранилища сертификат, установленный этой программой.</summary>
    [RelayCommand(CanExecute = nameof(CanRemoveFromStore))]
    private async Task RemoveFromStoreAsync()
    {
        var item = SelectedCertificate;
        if (item is null || RequestConfirmAsync is null)
            return;

        var confirmed = await RequestConfirmAsync(
            "Удаление из хранилища Windows",
            $"Удалить сертификат «{item.Subject}» из системного хранилища?\n\n"
            + "Другие программы перестанут его видеть. Сохранённая в этой программе "
            + "копия (PFX с паролем), если она есть, останется — подписывать здесь "
            + "можно будет по-прежнему.");
        if (!confirmed)
            return;

        try
        {
            await Task.Run(() => _vault.RemoveFromStore(item.Thumbprint, _settings));
            RefreshCertificates();
            StatusText = $"Сертификат «{item.Subject}» удалён из хранилища Windows.";
        }
        catch (Exception ex)
        {
            StatusText = "Удаление из хранилища: " + ex.Message;
        }
    }

    // Сертификат с закрытым ключом для подписания: из хранилища — как есть,
    // сохранённый на ПК — разблокируется паролем (кешируется на сеанс).
    private async Task<System.Security.Cryptography.X509Certificates.X509Certificate2?> ResolveSigningCertificateAsync(CertificateItem item)
    {
        if (item.Saved is null)
            return item.Certificate;
        if (item.Unlocked is not null)
            return item.Unlocked;
        if (RequestPasswordAsync is null)
            return null;

        var password = await RequestPasswordAsync(
            "Пароль сохранённого сертификата",
            $"Сертификат «{item.Subject}» сохранён на этом компьютере. "
            + "Введите пароль, заданный при сохранении.",
            null,
            false);
        if (password is null)
            return null;

        item.Unlocked = await Task.Run(() => _vault.Load(item.Saved, password));
        return item.Unlocked;
    }

    [RelayCommand(CanExecute = nameof(CanBrowse))]
    private void Browse() => BrowseRequested?.Invoke(this, EventArgs.Empty);

    private bool CanBrowse() => !IsBusy;

    /// <summary>
    /// Добавляет файлы в очередь. Файл подписи .sig прикладывается к своему
    /// документу для объединения, если документ уже в списке (по имени: "документ.pdf.sig"
    /// → "документ.pdf"); иначе пропускается.
    /// </summary>
    public void AddFiles(params string[] filePaths)
    {
        int added = 0, attached = 0, skippedSigs = 0;
        foreach (var path in filePaths)
        {
            if (string.IsNullOrWhiteSpace(path) || !System.IO.File.Exists(path))
                continue;

            if (path.EndsWith(".sig", StringComparison.OrdinalIgnoreCase))
            {
                var documentPath = path[..^4];
                var target = Files.FirstOrDefault(f =>
                    string.Equals(f.FilePath, documentPath, StringComparison.OrdinalIgnoreCase));
                if (target is not null)
                    attached += target.AttachSignatures(new[] { path });
                else
                    skippedSigs++;
                continue;
            }

            if (Files.Any(f => string.Equals(f.FilePath, path, StringComparison.OrdinalIgnoreCase)))
                continue;

            Files.Add(new SignFileItem(path));
            added++;
        }

        var parts = new List<string>();
        if (added > 0) parts.Add($"добавлено файлов: {added}");
        if (attached > 0) parts.Add($"приложено подписей: {attached}");
        if (skippedSigs > 0) parts.Add($"пропущено .sig без документа в списке: {skippedSigs}");
        if (parts.Count > 0)
        {
            var summary = string.Join(", ", parts);
            StatusText = char.ToUpper(summary[0]) + summary[1..] + $". Всего в очереди: {Files.Count}";
        }
    }

    /// <summary>Открыть диалог выбора подписей других лиц для файла.</summary>
    [RelayCommand]
    private void AttachSignatures(SignFileItem item) => AttachSignaturesRequested?.Invoke(this, item);

    [RelayCommand(CanExecute = nameof(CanBrowse))]
    private void Extract() => ExtractRequested?.Invoke(this, EventArgs.Empty);

    [RelayCommand(CanExecute = nameof(CanBrowse))]
    private void MergeFiles() => MergeFilesRequested?.Invoke(this, EventArgs.Empty);

    [RelayCommand(CanExecute = nameof(CanBrowse))]
    private void BuildContainer() => BuildContainerRequested?.Invoke(this, EventArgs.Empty);

    /// <summary>
    /// Собирает прикреплённый криптоконтейнер (документ + имеющиеся подписи)
    /// без создания своей подписи.
    /// </summary>
    public async Task BuildContainerAsync(string documentPath, IReadOnlyList<string>? signaturePaths)
    {
        IsBusy = true;
        try
        {
            var r = await Task.Run(() => CmsExtractor.BuildContainer(documentPath, signaturePaths));
            var parts = new List<string> { $"подписантов: {r.SignerCount}" };
            if (r.ExcludedSigners.Count > 0)
                parts.Add("исключены не соответствующие документу: " + string.Join("; ", r.ExcludedSigners));
            if (r.UnverifiedSigners.Count > 0)
                parts.Add("не удалось проверить: " + string.Join("; ", r.UnverifiedSigners));
            StatusText = $"Контейнер собран → «{System.IO.Path.GetFileName(r.OutputPath)}» ({string.Join(", ", parts)})";
        }
        catch (Exception ex)
        {
            StatusText = "Сборка контейнера: " + ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private bool CanStampOnly() => !IsBusy && SelectedCertificate is not null;

    [RelayCommand(CanExecute = nameof(CanStampOnly))]
    private void StampOnly() => StampOnlyRequested?.Invoke(this, EventArgs.Empty);

    /// <summary>
    /// Ставит визуальный штамп на выбранные PDF без подписания: рядом сохраняется
    /// копия «имя (со штампом).pdf». Пароль не нужен — используются только
    /// данные сертификата (открытая часть).
    /// </summary>
    public async Task StampWithoutSigningAsync(IReadOnlyList<string> pdfPaths)
    {
        if (pdfPaths.Count == 0 || SelectedCertificate is not { } item)
            return;

        IsBusy = true;
        try
        {
            var lines = new List<string>();
            foreach (var path in pdfPaths)
            {
                try
                {
                    if (!PdfStamper.IsPdf(path))
                    {
                        lines.Add($"«{System.IO.Path.GetFileName(path)}»: пропущен (не PDF)");
                        continue;
                    }

                    var stamped = await Task.Run(() => PdfStamper.CreateStampedCopy(
                        path, item.Certificate, StampWithDate, StampLogoPath, DateTime.Now));
                    lines.Add($"«{System.IO.Path.GetFileName(path)}» → «{System.IO.Path.GetFileName(stamped)}»");
                }
                catch (Exception ex)
                {
                    lines.Add($"«{System.IO.Path.GetFileName(path)}»: ошибка — {ex.Message}");
                }
            }

            StatusText = "Штамп без подписания: " + string.Join(" | ", lines);
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>Объединяет выбранные файлы подписей в один — без создания своей подписи.</summary>
    public async Task MergeSignatureFilesAsync(IReadOnlyList<string> paths)
    {
        if (paths.Count == 0)
            return;

        IsBusy = true;
        try
        {
            var r = await Task.Run(() => CmsExtractor.MergeSignatureFiles(paths));
            var parts = new List<string>
            {
                $"подписантов: {r.SignerCount}",
                r.AttachedOutput ? "прикреплённая (документ внутри)" : "откреплённая",
                r.DocumentNote,
            };
            if (r.ExcludedSigners.Count > 0)
                parts.Add("исключены не соответствующие документу: " + string.Join("; ", r.ExcludedSigners));
            if (r.UnverifiedSigners.Count > 0)
                parts.Add("не удалось проверить: " + string.Join("; ", r.UnverifiedSigners));

            StatusText = $"Объединено → «{System.IO.Path.GetFileName(r.OutputPath)}»: {string.Join(", ", parts)}";
        }
        catch (Exception ex)
        {
            StatusText = "Объединение не выполнено: " + ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>Извлекает содержимое выбранных контейнеров в файлы рядом с ними.</summary>
    public async Task ExtractContainersAsync(IReadOnlyList<string> containerPaths)
    {
        if (containerPaths.Count == 0)
            return;

        IsBusy = true;
        try
        {
            var lines = new List<string>();
            foreach (var path in containerPaths)
            {
                try
                {
                    var r = await Task.Run(() => CmsExtractor.ExtractToFiles(path));
                    var parts = new List<string>();
                    if (r.DocumentPath is not null)
                        parts.Add($"документ → {System.IO.Path.GetFileName(r.DocumentPath)}");
                    if (r.DetachedPath is not null)
                        parts.Add($"откреплённая подпись → {System.IO.Path.GetFileName(r.DetachedPath)}");
                    if (r.SignerFiles.Count > 0)
                        parts.Add($"подписи по подписантам: {r.SignerFiles.Count}");
                    if (parts.Count == 0)
                        parts.Add($"уже откреплённая, подписантов: {r.SignerCount} — извлекать нечего");
                    lines.Add($"«{r.ContainerName}»: {string.Join(", ", parts)}");
                }
                catch (Exception ex)
                {
                    lines.Add($"«{System.IO.Path.GetFileName(path)}»: ошибка — {ex.Message}");
                }
            }

            StatusText = "Извлечение: " + string.Join(" | ", lines);
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void RemoveFile(SignFileItem item) => Files.Remove(item);

    [RelayCommand(CanExecute = nameof(CanClear))]
    private void Clear()
    {
        Files.Clear();
        StatusText = "Список файлов очищен";
    }

    private bool CanClear() => !IsBusy;

    private bool CanSignAll() =>
        !IsBusy && SelectedCertificate is not null && Files.Count > 0;

    [RelayCommand(CanExecute = nameof(CanSignAll))]
    private async Task SignAllAsync()
    {
        System.Security.Cryptography.X509Certificates.X509Certificate2? certificate;
        try
        {
            certificate = await ResolveSigningCertificateAsync(SelectedCertificate!);
        }
        catch (Exception ex)
        {
            StatusText = ex.Message;
            return;
        }

        if (certificate is null)
        {
            StatusText = "Подписание отменено: сертификат не разблокирован.";
            return;
        }

        IsBusy = true;

        var signed = 0;
        var failed = 0;

        try
        {
            foreach (var file in Files.Where(f => f.Status != SignStatus.Signed).ToList())
            {
                file.Status = SignStatus.Signing;
                StatusText = $"Подписание: {file.FileName}";

                try
                {
                    // Task.Run: подпись может блокировать (диалог PIN-кода CSP),
                    // не держим UI-поток.
                    var options = new DocumentSigner.SignOptions
                    {
                        Detached = IsDetached,
                        MergeWithExisting = MergeWithExisting,
                        ExtraSignatures = file.ExtraSignatures,
                        Timestamp = UseTimestamp,
                        TsaUrl = TsaUrl,
                        Stamp = UseStamp,
                        StampWithDate = StampWithDate,
                        StampLogoPath = StampLogoPath,
                    };
                    var result = await Task.Run(
                        () => _documentSigner.SignFileAsync(file.FilePath, certificate, options));
                    file.SignaturePath = result.SignaturePath;
                    file.SignerCount = result.SignerCount;

                    var notes = new List<string>();
                    if (result.ExcludedSigners.Count > 0)
                        notes.Add("исключены не соответствующие документу подписи: "
                                  + string.Join("; ", result.ExcludedSigners));
                    if (result.UnverifiedSigners.Count > 0)
                        notes.Add("не удалось проверить: " + string.Join("; ", result.UnverifiedSigners));
                    file.Message = notes.Count > 0 ? string.Join(". ", notes) : null;

                    file.Status = SignStatus.Signed;
                    signed++;
                    Log($"  [OK] {file.FileName} → {System.IO.Path.GetFileName(result.SignaturePath)}"
                        + (result.SignerCount > 1 ? $" (подписантов: {result.SignerCount})" : "")
                        + (file.Message is null ? "" : $". {file.Message}"));
                }
                catch (Exception ex)
                {
                    file.Message = ex.Message;
                    file.Status = SignStatus.Failed;
                    failed++;
                    Log($"  [ОШИБКА] {file.FileName}: {ex.Message}");
                }
            }
        }
        finally
        {
            IsBusy = false;
        }

        StatusText = failed == 0
            ? $"Готово. Подписано файлов: {signed}"
            : $"Подписано: {signed}, с ошибками: {failed}";
    }
}
