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
    private readonly CertificateVault _vault;
    private readonly AppSettings _settings;
    private bool _initializing;

    // Отпечаток выбранного сертификата: список пересоздаёт элементы при обновлении,
    // поэтому смену сертификата определяем по отпечатку, а не по экземпляру.
    private string? _activeThumbprint;

    public MainWindowViewModel(CertificateProvider certificateProvider, DocumentSigner documentSigner)
        : this(certificateProvider, documentSigner, AppSettings.Load())
    {
    }

    /// <summary>С явными настройками и папкой сохранённых сертификатов — для тестов.</summary>
    public MainWindowViewModel(CertificateProvider certificateProvider, DocumentSigner documentSigner,
        AppSettings settings, CertificateVault? vault = null)
    {
        _certificateProvider = certificateProvider;
        _documentSigner = documentSigner;
        _settings = settings;
        _vault = vault ?? new CertificateVault();

        _initializing = true;
        IsDetached = _settings.DetachedSignature;
        MergeWithExisting = _settings.MergeWithExisting;
        CreateSignatureBackup = _settings.CreateSignatureBackup;
        ApplyCoSignToAll = _settings.ApplyCoSignToAll;
        UseTimestamp = _settings.UseTimestamp;
        TsaUrl = _settings.TsaUrl;
        UseStamp = _settings.UseStamp;
        StampWithDate = _settings.StampWithDate;
        StampSignCopy = _settings.StampSignCopy;
        StampLogoPath = _settings.StampLogoPath;
        _initializing = false;

        Files.CollectionChanged += (_, _) => SignAllCommand.NotifyCanExecuteChanged();
        RefreshCertificates();

        // Восстанавливаем ранее добавленную МЧД: повторная проверка идёт в фоне.
        if (_settings.PoaXmlPath is { } poaXml && _settings.PoaSigPath is { } poaSig)
            _ = SetPoaAsync(poaXml, poaSig, restoring: true);

        _ = CheckUpdatesOnStartAsync();
    }

    /// <summary>Настройки приложения — для окна «О программе».</summary>
    public AppSettings Settings => _settings;

    /// <summary>Версия программы для нижней строки главного окна.</summary>
    public string VersionDisplay => "Версия " + UpdateService.CurrentVersion;

    // Тихая проверка обновлений при запуске: при наличии новой версии — строка
    // в статусе/логе, никаких всплывающих окон.
    private async Task CheckUpdatesOnStartAsync()
    {
        if (!_settings.CheckUpdatesOnStart)
            return;

        try
        {
            var update = await new UpdateService().CheckForUpdateAsync();
            if (update is not null)
                StatusText = $"Доступна новая версия {update.Version} — обновиться можно в окне «О программе».";
        }
        catch (Exception)
        {
            // нет сети или GitHub недоступен — не мешаем работе
        }
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

    /// <summary>Сохранять .bak перед любой перезаписью существующего .sig.</summary>
    [ObservableProperty]
    private bool _createSignatureBackup;

    /// <summary>Режим первого файла в очереди применяется ко всем остальным.</summary>
    [ObservableProperty]
    private bool _applyCoSignToAll;

    private bool _syncingCoSign;

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

    /// <summary>
    /// true — подписывать копию со штампом (как раньше); false — подписывать
    /// оригинал, а копию со штампом всех подписантов сохранять отдельно без
    /// подписи (безопасно при соподписании).
    /// </summary>
    [ObservableProperty]
    private bool _stampSignCopy;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StampLogoDisplay))]
    private string? _stampLogoPath;

    public string StampLogoDisplay => StampLogoPath is null
        ? "лого не выбрано"
        : System.IO.Path.GetFileName(StampLogoPath);

    /// <summary>Запрос диалога выбора картинки логотипа для штампа.</summary>
    public event EventHandler? PickLogoRequested;

    /// <summary>Доверенность МЧД, приложенная к подписанию (null — без доверенности).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PoaDisplay))]
    [NotifyPropertyChangedFor(nameof(HasPoa))]
    private PowerOfAttorneyService.PoaInfo? _poa;

    public bool HasPoa => Poa is not null;

    public string PoaDisplay => Poa is null
        ? "доверенность не добавлена"
        : $"МЧД № {Poa.Number}" + (Poa.ValidTo is { } v ? $" до {v:dd.MM.yyyy}" : "");

    /// <summary>Запрос диалогов выбора файлов МЧД (XML и подписи руководителя).</summary>
    public event EventHandler? AddPoaRequested;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SignAllCommand))]
    [NotifyCanExecuteChangedFor(nameof(BrowseCommand))]
    [NotifyCanExecuteChangedFor(nameof(ClearCommand))]
    [NotifyCanExecuteChangedFor(nameof(SaveCertificateCommand))]
    [NotifyCanExecuteChangedFor(nameof(DeleteCertificateCommand))]
    [NotifyCanExecuteChangedFor(nameof(InstallCertificateCommand))]
    [NotifyCanExecuteChangedFor(nameof(RemoveFromStoreCommand))]
    [NotifyCanExecuteChangedFor(nameof(StampOnlyCommand))]
    [NotifyCanExecuteChangedFor(nameof(ExtractCommand))]
    [NotifyCanExecuteChangedFor(nameof(BuildContainerCommand))]
    [NotifyCanExecuteChangedFor(nameof(VerifySignatureCommand))]
    [NotifyCanExecuteChangedFor(nameof(SplitSignaturesCommand))]
    [NotifyCanExecuteChangedFor(nameof(RemoveSignerCommand))]
    [NotifyCanExecuteChangedFor(nameof(AttachSignaturesCommand))]
    [NotifyCanExecuteChangedFor(nameof(StampItemCommand))]
    [NotifyCanExecuteChangedFor(nameof(ExtractItemCommand))]
    [NotifyCanExecuteChangedFor(nameof(BuildContainerItemCommand))]
    [NotifyCanExecuteChangedFor(nameof(SplitItemCommand))]
    [NotifyCanExecuteChangedFor(nameof(RemoveSignerItemCommand))]
    private bool _isBusy;

    [ObservableProperty]
    private string _statusText = "Перетащите файлы в окно или добавьте их через «Обзор…»";

    /// <summary>Текст окна лога (всегда видимого): все операции с отметкой времени.</summary>
    [ObservableProperty]
    private string _logText = "";

    // Каждая смена статуса попадает в лог — статусная строка в UI не дублируется.
    partial void OnStatusTextChanged(string value) => Log(value);

    private void Log(string message)
    {
        if (string.IsNullOrWhiteSpace(message))
            return;
        LogText += $"[{DateTime.Now:HH:mm:ss}] {message}\n";
    }

    [RelayCommand]
    private void ClearLog() => LogText = "";

    /// <summary>
    /// Запрос диалога параметров штампа (реализуется окном).
    /// Параметр — показывать ли пункт «подписывать копию со штампом».
    /// </summary>
    public Func<bool, Task<Views.StampOptionsDialog.Result?>>? RequestStampOptionsAsync { get; set; }

    /// <summary>
    /// Запрос диалога выбора файлов; обрабатывается в MainWindow,
    /// т.к. StorageProvider доступен только на уровне окна.
    /// </summary>
    public event EventHandler? BrowseRequested;

    /// <summary>Запрос диалога выбора .sig других лиц для объединения с подписью файла.</summary>
    public event EventHandler<SignFileItem>? AttachSignaturesRequested;

    /// <summary>Запрос диалога выбора контейнеров для извлечения.</summary>
    public event EventHandler? ExtractRequested;

    /// <summary>Запрос диалога выбора PDF для штампа без подписания.</summary>
    public event EventHandler? StampOnlyRequested;

    /// <summary>Запрос диалога выбора документа для сборки криптоконтейнера.</summary>
    public event EventHandler? BuildContainerRequested;

    /// <summary>Запрос диалога выбора групповых подписей для разделения.</summary>
    public event EventHandler? SplitSignaturesRequested;

    /// <summary>Запрос диалога выбора подписи, из которой исключается подписант.</summary>
    public event EventHandler? RemoveSignerRequested;

    /// <summary>Выбор исключаемого подписанта (реализуется окном): Id или null при отмене.</summary>
    public Func<IReadOnlyList<CmsExtractor.SignerInfo>, Task<string?>>? RequestSignerChoiceAsync { get; set; }

    /// <summary>
    /// Открыть окно «Проверка ЭЦП» (реализуется окном). Пути подписи и документа
    /// необязательны: если подпись указана, проверка запускается сразу.
    /// Возвращает краткий итог последней проверки для лога (null — проверки не было).
    /// </summary>
    public Func<string?, string?, Task<string?>>? ShowVerificationAsync { get; set; }

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
        if (value is null)
            return;

        // Смена сертификата позволяет соподписать уже обработанные файлы. Обновление
        // списка (тот же отпечаток, новый элемент) статусы не сбрасывает.
        var changed = _activeThumbprint is not null
            && !string.Equals(_activeThumbprint, value.Thumbprint, StringComparison.OrdinalIgnoreCase);
        _activeThumbprint = value.Thumbprint;
        if (changed)
        {
            var requeued = 0;
            foreach (var file in Files.Where(f => f.Status == SignStatus.Signed))
            {
                file.ResetForSigning();
                requeued++;
            }

            if (requeued > 0)
                Log($"Сертификат сменён: подписанные файлы ({requeued}) снова в очереди — для соподписания.");
        }

        if (_initializing)
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
        if (!_initializing)
        {
            _settings.MergeWithExisting = value;
            _settings.Save();
        }

        foreach (var file in Files)
            file.ApplyPreferredMode(value, resetPin: !_initializing);
        if (ApplyCoSignToAll)
            SyncSharedCoSignMode();
    }

    partial void OnCreateSignatureBackupChanged(bool value)
    {
        if (!_initializing)
        {
            _settings.CreateSignatureBackup = value;
            _settings.Save();
        }

        foreach (var file in Files)
            file.SetBackupMention(value);
    }

    partial void OnApplyCoSignToAllChanged(bool value)
    {
        if (!_initializing)
        {
            _settings.ApplyCoSignToAll = value;
            _settings.Save();
        }

        SyncSharedCoSignMode();
    }

    /// <summary>Смена режима в строке: при «Применить ко всем» источник — первый файл.</summary>
    internal void NotifyCoSignSelectionChanged(SignFileItem item)
    {
        if (_syncingCoSign || !ApplyCoSignToAll || Files.Count == 0 || !ReferenceEquals(Files[0], item))
            return;
        SyncSharedCoSignMode();
    }

    private void SyncSharedCoSignMode()
    {
        if (_syncingCoSign)
            return;
        _syncingCoSign = true;
        try
        {
            var add = Files.Count > 0 && Files[0].SelectedCoSignOption is { CreateNew: false };
            for (var i = 0; i < Files.Count; i++)
            {
                var file = Files[i];
                file.CoSignLocked = ApplyCoSignToAll && i > 0;
                if (!ApplyCoSignToAll || i == 0)
                    file.StopFollowingSharedMode();
                else
                    file.FollowSharedMode(add);
            }
        }
        finally
        {
            _syncingCoSign = false;
        }
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
        UpdateStampedCopyMode();
        if (_initializing) return;
        _settings.UseStamp = value;
        _settings.Save();
    }

    // В режиме «подписывать копию со штампом» найденные подписи оригинала к подписи не относятся.
    private bool SignsStampedCopy(SignFileItem file) => UseStamp && StampSignCopy && PdfStamper.IsPdf(file.FilePath);

    private void UpdateStampedCopyMode()
    {
        foreach (var file in Files)
            file.SignsStampedCopy = SignsStampedCopy(file);
    }

    partial void OnStampWithDateChanged(bool value)
    {
        if (_initializing) return;
        _settings.StampWithDate = value;
        _settings.Save();
    }

    partial void OnStampSignCopyChanged(bool value)
    {
        UpdateStampedCopyMode();
        if (_initializing) return;
        _settings.StampSignCopy = value;
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

    [RelayCommand(CanExecute = nameof(CanBrowse))]
    private void AddPoa() => AddPoaRequested?.Invoke(this, EventArgs.Empty);

    [RelayCommand]
    private void ClearPoa()
    {
        Poa = null;
        _settings.PoaXmlPath = null;
        _settings.PoaSigPath = null;
        _settings.Save();
        StatusText = "Доверенность (МЧД) убрана — подписание пойдёт без неё.";
    }

    /// <summary>
    /// Загружает и проверяет доверенность МЧД (как Контур: XML + подпись
    /// руководителя, проверка подписи, срока и соответствия представителя
    /// выбранному сертификату). Проверка цепочки и отзыва идёт в фоне, на это
    /// время команды недоступны. При восстановлении после запуска итог — в лог.
    /// </summary>
    public async Task SetPoaAsync(string xmlPath, string sigPath, bool restoring = false)
    {
        var prefix = restoring ? "Сохранённая МЧД: " : "";
        IsBusy = true;
        try
        {
            var options = CreateVerificationOptions();
            var certificate = SelectedCertificate?.Certificate;
            var (info, check) = await Task.Run(() =>
            {
                var parsed = PowerOfAttorneyService.Parse(xmlPath, sigPath);
                return (parsed, PowerOfAttorneyService.Validate(parsed, certificate, options));
            });

            if (check.State == PowerOfAttorneyService.CheckState.Error)
            {
                Poa = null;
                Report("Доверенность НЕ добавлена: " + check.Message);
                return;
            }

            Poa = info;
            _settings.PoaXmlPath = xmlPath;
            _settings.PoaSigPath = sigPath;
            _settings.Save();

            var summary = $"Добавлена МЧД № {info.Number}"
                + (info.ValidTo is { } v ? $" (до {v:dd.MM.yyyy})" : "")
                + $", доверитель: {info.PrincipalOrg}, представитель: {info.RepresentativeName}. "
                + check.Message;
            Report(check.State == PowerOfAttorneyService.CheckState.Warning ? "⚠ " + summary : summary);
        }
        catch (Exception ex)
        {
            Poa = null;
            Report("Не удалось загрузить МЧД: " + ex.Message);
        }
        finally
        {
            IsBusy = false;
        }

        void Report(string message)
        {
            if (restoring)
                Log(prefix + message);
            else
                StatusText = message;
        }
    }

    // Параметры проверки ЭЦП из настроек; пропущенные файлы доверенных корней — в лог.
    private VerificationOptions CreateVerificationOptions()
    {
        var problems = new List<string>();
        var options = _settings.CreateVerificationOptions(problems);
        foreach (var problem in problems)
            Log("⚠ " + problem);
        return options;
    }

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

    // Доступно и для сертификата из системного хранилища (ключ на токене):
    // тогда установка сначала сохранит копию в программе (PFX), затем поставит
    // её в хранилище — одним действием.
    private bool CanInstallCertificate() =>
        !IsBusy && SelectedCertificate is { } sel
            && (sel.IsSaved
                || _settings.SavedCertificates.Any(c =>
                    string.Equals(c.Thumbprint, sel.Thumbprint, StringComparison.OrdinalIgnoreCase))
                || sel.Certificate.HasPrivateKey);

    /// <summary>
    /// Устанавливает сертификат в системное хранилище Windows с копией закрытого
    /// ключа — чтобы им можно было подписывать и в ДРУГИХ программах (КриптоАРМ,
    /// браузер и т.д.) без подключённого ключа ЭЦП. Для сертификата с токена
    /// ключ сначала экспортируется в PFX программы, затем копия устанавливается
    /// в хранилище (существующая запись, указывающая на токен, заменяется).
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanInstallCertificate))]
    private async Task InstallCertificateAsync()
    {
        if (SelectedCertificate is not { } item || RequestPasswordAsync is null)
            return;

        var saved = item.Saved ?? _settings.SavedCertificates.FirstOrDefault(c =>
            string.Equals(c.Thumbprint, item.Thumbprint, StringComparison.OrdinalIgnoreCase));

        try
        {
            if (saved is null)
            {
                // Сертификат из хранилища (обычно ключ на токене): экспорт + установка.
                var password = await RequestPasswordAsync(
                    "Установка сертификата в хранилище Windows",
                    $"Сертификат «{item.Subject}» будет скопирован с ключа ЭЦП: сохранён "
                    + "в программе (PFX, защищённый паролем) и установлен в хранилище Windows "
                    + "(«Текущий пользователь → Личное») с копией закрытого ключа.",
                    "⚠ ВНИМАНИЕ: закрытый ключ будет экспортирован с токена и останется на этом "
                    + "компьютере. Подписывать им смогут ВСЕ программы под вашей учётной записью "
                    + "Windows — уже без токена и без пароля этой программы. Существующая запись "
                    + "в хранилище, указывающая на токен, будет заменена копией. Это менее "
                    + "безопасно, чем токен: устанавливайте только на личном компьютере и удалите "
                    + "из хранилища, когда перестанет быть нужен. Если ключ на токене помечен как "
                    + "неэкспортируемый, операция завершится ошибкой — это ограничение токена.",
                    true);
                if (password is null)
                    return;

                var certificate = await ResolveSigningCertificateAsync(item);
                if (certificate is null)
                    return;

                saved = await Task.Run(() => _vault.Save(certificate, password, _settings));
                await Task.Run(() => _vault.InstallToStore(saved, password, _settings));
            }
            else
            {
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

                await Task.Run(() => _vault.InstallToStore(saved, password, _settings));
            }

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

    /// <summary>Добавляет файлы в очередь; подписи документов ищутся в фоне (см. <see cref="AddFilesAsync"/>).</summary>
    public void AddFiles(params string[] filePaths) => _ = AddFilesAsync(filePaths);

    /// <summary>
    /// Добавляет файлы в очередь. Для документов в фоне ищутся подписи в их папке
    /// по содержимому (имя .sig может не совпадать с документом). Перетащенный файл
    /// подписи прикладывается к документам очереди, к которым относится по содержимому,
    /// иначе — к документу с именем «документ» для «документ.sig»; несопоставленные
    /// перечисляются в статусе.
    /// </summary>
    public async Task AddFilesAsync(params string[] filePaths)
    {
        var signatures = new List<string>();
        var added = new List<SignFileItem>();
        foreach (var path in filePaths)
        {
            if (string.IsNullOrWhiteSpace(path) || !System.IO.File.Exists(path))
                continue;

            if (SignatureDiscovery.IsSignatureFile(path))
            {
                if (!signatures.Any(existing => SignatureDiscovery.SamePath(existing, path)))
                    signatures.Add(path);
                continue;
            }

            if (Files.Any(file => SignatureDiscovery.SamePath(file.FilePath, path)))
                continue;

            var item = new SignFileItem(path) { Owner = this };
            item.SetBackupMention(CreateSignatureBackup);
            item.SignsStampedCopy = SignsStampedCopy(item);
            Files.Add(item);
            added.Add(item);
        }

        if (added.Count > 0)
            StatusText = $"Добавлено файлов: {added.Count}. Всего в очереди: {Files.Count}";

        // Новые документы ищут подписи в своей папке; перетащенные подписи сверяются со всей
        // очередью. Во время подписания план уже стоявших файлов не меняется.
        var targets = signatures.Count > 0 ? Files.ToList() : added;
        var refresh = IsBusy ? added : targets;
        var result = await DiscoverAsync(targets, signatures, refresh);

        var unmatched = new List<string>();
        var attached = result.Attached;
        foreach (var path in signatures.Where(path => !result.MatchedSignatures.Contains(System.IO.Path.GetFullPath(path))))
        {
            var sibling = SignatureDiscovery.SiblingDocumentPath(path);
            var named = sibling is null ? null : Files.FirstOrDefault(file => SignatureDiscovery.SamePath(file.FilePath, sibling));
            if (named is not null)
                attached += named.AttachSignatures(new[] { path });
            else
                unmatched.Add(System.IO.Path.GetFileName(path));
        }

        var parts = new List<string>();
        if (result.Found > 0)
            parts.Add($"найдены подписи в папке для документов: {result.Found}");
        if (attached > 0)
            parts.Add($"приложено подписей: {attached}");
        if (unmatched.Count > 0)
            parts.Add("не сопоставлены с документами в очереди: "
                + string.Join(", ", unmatched.Select(name => "«" + name + "»")));
        if (parts.Count > 0)
        {
            var summary = string.Join(", ", parts);
            StatusText = char.ToUpper(summary[0]) + summary[1..] + ".";
        }
    }

    private sealed record DiscoveryOutcome(int Found, int Attached, ISet<string> MatchedSignatures);

    // Сколько фоновых поисков подписей идёт: подписание ждёт их завершения.
    private int _discoveryRuns;

    /// <summary>Идёт поиск подписей для документов очереди.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SignAllCommand))]
    private bool _isDiscovering;

    partial void OnIsBusyChanged(bool value)
    {
        foreach (var file in Files)
            file.NotifyBusyChanged();
    }

    // Поиск подписей в фоне: каждый документ читается и хешируется один раз. Варианты
    // соподписания обновляются в потоке интерфейса только у файлов из refresh.
    private async Task<DiscoveryOutcome> DiscoverAsync(IReadOnlyList<SignFileItem> targets,
        IReadOnlyList<string> droppedSignatures, IReadOnlyCollection<SignFileItem> refresh)
    {
        var matched = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (targets.Count == 0)
            return new DiscoveryOutcome(0, 0, matched);

        var fresh = refresh.Where(item => !item.IsDiscovering && targets.Contains(item)).ToList();
        foreach (var item in fresh)
            item.IsDiscovering = true;
        _discoveryRuns++;
        IsDiscovering = true;
        try
        {
            var documents = targets.Select(item => item.FilePath).ToList();
            IReadOnlyList<SignatureDiscovery.DocumentDiscovery> found;
            try
            {
                found = await Task.Run(() => SignatureDiscovery.Discover(documents, droppedSignatures));
            }
            catch (Exception ex)
            {
                Log("Поиск подписей не выполнен: " + ex.Message);
                return new DiscoveryOutcome(0, 0, matched);
            }

            var withMatches = 0;
            var attached = 0;
            for (var i = 0; i < targets.Count && i < found.Count; i++)
            {
                var item = targets[i];
                var discovery = found[i];
                if (fresh.Contains(item))
                {
                    item.ApplyDiscovery(discovery, MergeWithExisting);
                    if (discovery.FolderMatches.Any(match => match.MatchingSigners > 0))
                        withMatches++;
                }

                var dropped = discovery.DroppedMatches.Select(match => match.Path).ToList();
                if (dropped.Count == 0)
                    continue;
                attached += item.AttachSignatures(dropped);
                foreach (var path in dropped)
                    matched.Add(System.IO.Path.GetFullPath(path));
            }

            if (ApplyCoSignToAll)
                SyncSharedCoSignMode();
            return new DiscoveryOutcome(withMatches, attached, matched);
        }
        finally
        {
            foreach (var item in fresh)
                item.IsDiscovering = false;
            if (--_discoveryRuns == 0)
                IsDiscovering = false;
        }
    }

    /// <summary>Подписи, выбранные кнопкой «＋.sig»: приложить к файлу (будут объединены с вашей).</summary>
    public void AttachSignatureFiles(SignFileItem item, IReadOnlyList<string> paths)
    {
        var added = item.AttachSignatures(paths);
        if (added > 0)
            StatusText = $"Приложено подписей к «{item.FileName}»: {added} (всего: {item.ExtraCount})";
        else if (paths.Count > 0)
            StatusText = $"К «{item.FileName}» не добавлено новых подписей.";
    }

    /// <summary>Открыть диалог выбора подписей других лиц для файла.</summary>
    [RelayCommand(CanExecute = nameof(CanBrowse))]
    private void AttachSignatures(SignFileItem item) => AttachSignaturesRequested?.Invoke(this, item);

    [RelayCommand(CanExecute = nameof(CanBrowse))]
    private void Extract() => ExtractRequested?.Invoke(this, EventArgs.Empty);

    [RelayCommand(CanExecute = nameof(CanBrowse))]
    private void BuildContainer() => BuildContainerRequested?.Invoke(this, EventArgs.Empty);

    [RelayCommand(CanExecute = nameof(CanBrowse))]
    private Task VerifySignature() => OpenVerificationAsync(null, null);

    private async Task OpenVerificationAsync(string? signaturePath, string? documentPath)
    {
        if (ShowVerificationAsync is null)
            return;
        var summary = await ShowVerificationAsync(signaturePath, documentPath);
        if (summary is not null)
            StatusText = summary;
    }

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

    /// <summary>Начальные параметры диалога штампа — из сохранённых настроек.</summary>
    public PdfStamper.StampOptions BuildInitialStampOptions() => new()
    {
        WithDate = StampWithDate,
        LogoPath = StampLogoPath,
        Pages = Enum.TryParse<PdfStamper.StampPages>(_settings.StampPagesMode, out var p)
            ? p
            : PdfStamper.StampPages.Last,
        CustomPages = _settings.StampCustomPages,
    };

    /// <summary>Запоминает параметры, выбранные в диалоге штампа.</summary>
    public void SaveStampOptions(Views.StampOptionsDialog.Result result)
    {
        StampWithDate = result.Options.WithDate;
        StampLogoPath = result.Options.LogoPath;
        StampSignCopy = result.SignCopy;
        _settings.StampPagesMode = result.Options.Pages.ToString();
        _settings.StampCustomPages = result.Options.CustomPages;
        _settings.Save();
    }

    /// <summary>
    /// Ставит визуальный штамп на PDF без подписания. Если рядом с документом
    /// есть «имя.sig», плашки ставятся для ВСЕХ его подписантов; иначе —
    /// по данным выбранного сертификата.
    /// </summary>
    public async Task StampWithoutSigningAsync(IReadOnlyList<string> pdfPaths, PdfStamper.StampOptions options,
        string? signatureHint = null)
    {
        if (pdfPaths.Count == 0 || SelectedCertificate is not { } item)
            return;

        options = options with { PoaNumber = options.PoaNumber ?? Poa?.Number };
        IsBusy = true;
        try
        {
            foreach (var path in pdfPaths)
            {
                var name = System.IO.Path.GetFileName(path);
                try
                {
                    if (!PdfStamper.IsPdf(path))
                    {
                        Log($"«{name}»: пропущен (не PDF)");
                        continue;
                    }

                    var stamped = await Task.Run(() =>
                    {
                        var sigPath = signatureHint ?? path + ".sig";
                        var certs = System.IO.File.Exists(sigPath)
                            ? CmsMerger.GetSignerCertificates(System.IO.File.ReadAllBytes(sigPath))
                            : Array.Empty<System.Security.Cryptography.X509Certificates.X509Certificate2>();
                        try
                        {
                            return PdfStamper.CreateStampedCopy(
                                path,
                                certs.Count > 0 ? certs : new[] { item.Certificate },
                                options,
                                DateTime.Now);
                        }
                        finally
                        {
                            foreach (var c in certs)
                                c.Dispose();
                        }
                    });
                    Log($"Штамп без подписания: «{name}» → «{System.IO.Path.GetFileName(stamped)}»");
                }
                catch (Exception ex)
                {
                    Log($"Штамп без подписания: «{name}» — ошибка: {ex.Message}");
                }
            }
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>ПКМ: подписанты и проверка ЭЦП для файла из списка (.sig рядом).</summary>
    [RelayCommand]
    private async Task InspectSignaturesAsync(SignFileItem item)
    {
        var sigPath = item.SignaturePathForTools();
        if (!System.IO.File.Exists(sigPath))
        {
            StatusText = $"Для «{item.FileName}» не найден файл подписи (ни «{System.IO.Path.GetFileName(item.FilePath)}.sig», ни подпись по хешу документа).";
            return;
        }

        await OpenVerificationAsync(sigPath, item.FilePath);
    }

    /// <summary>ПКМ: штамп для файла из списка (диалог параметров → копия без подписи).</summary>
    [RelayCommand(CanExecute = nameof(CanBrowse))]
    private async Task StampItemAsync(SignFileItem item)
    {
        if (RequestStampOptionsAsync is null)
            return;
        var result = await RequestStampOptionsAsync(false);
        if (result is null)
            return;
        SaveStampOptions(result);
        var signature = item.SignaturePathForTools();
        await StampWithoutSigningAsync(new[] { item.FilePath }, result.Options,
            System.IO.File.Exists(signature) ? signature : null);
    }

    /// <summary>ПКМ: извлечь из контейнера «имя.sig» рядом с файлом.</summary>
    [RelayCommand(CanExecute = nameof(CanBrowse))]
    private async Task ExtractItemAsync(SignFileItem item)
    {
        var sigPath = item.SignaturePathForTools();
        if (!System.IO.File.Exists(sigPath))
        {
            StatusText = $"Для «{item.FileName}» нет файла подписи для извлечения.";
            return;
        }

        await ExtractContainersAsync(new[] { sigPath });
    }

    /// <summary>ПКМ: собрать криптоконтейнер из файла и его подписи рядом.</summary>
    [RelayCommand(CanExecute = nameof(CanBrowse))]
    private Task BuildContainerItemAsync(SignFileItem item)
    {
        var signatures = item.DiscoveredMatches.Select(match => match.Path).ToList();
        var canonical = item.FilePath + ".sig";
        if (System.IO.File.Exists(canonical)
            && signatures.All(path => !SignatureDiscovery.SamePath(path, canonical)))
            signatures.Insert(0, canonical);
        return BuildContainerAsync(item.FilePath, signatures.Count > 0 ? signatures : null);
    }

    /// <summary>ПКМ: разделить групповую подпись «имя.sig» рядом с файлом по подписантам.</summary>
    [RelayCommand(CanExecute = nameof(CanBrowse))]
    private async Task SplitItemAsync(SignFileItem item)
    {
        var sigPath = item.SignaturePathForTools();
        if (!System.IO.File.Exists(sigPath))
        {
            StatusText = $"Для «{item.FileName}» нет файла подписи для разделения.";
            return;
        }

        await SplitSignatureFilesAsync(new[] { sigPath });
    }

    /// <summary>ПКМ: исключить подписанта из «имя.sig» рядом с файлом.</summary>
    [RelayCommand(CanExecute = nameof(CanBrowse))]
    private async Task RemoveSignerItemAsync(SignFileItem item)
    {
        var sigPath = item.SignaturePathForTools();
        if (!System.IO.File.Exists(sigPath))
        {
            StatusText = $"Для «{item.FileName}» нет файла подписи.";
            return;
        }

        await RemoveSignerFromFileAsync(sigPath);
    }

    [RelayCommand(CanExecute = nameof(CanBrowse))]
    private void SplitSignatures() => SplitSignaturesRequested?.Invoke(this, EventArgs.Empty);

    [RelayCommand(CanExecute = nameof(CanBrowse))]
    private void RemoveSigner() => RemoveSignerRequested?.Invoke(this, EventArgs.Empty);

    /// <summary>Разделяет групповые подписи на отдельные .sig по подписантам.</summary>
    public async Task SplitSignatureFilesAsync(IReadOnlyList<string> paths)
    {
        if (paths.Count == 0)
            return;

        IsBusy = true;
        try
        {
            foreach (var path in paths)
            {
                var name = System.IO.Path.GetFileName(path);
                try
                {
                    var r = await Task.Run(() => CmsExtractor.SplitSignatureFile(path));
                    StatusText = $"«{name}»: создано отдельных подписей: {r.SignerFiles.Count} ("
                        + string.Join(", ", r.SignerFiles.Select(System.IO.Path.GetFileName)) + ")"
                        + (r.DocumentPath is null ? "" : $"; документ → {System.IO.Path.GetFileName(r.DocumentPath)}");
                }
                catch (Exception ex)
                {
                    StatusText = $"Разделение «{name}»: {ex.Message}";
                }
            }
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>
    /// Исключает подписанта: выбор в диалоге → новый файл «имя (без подписанта).sig»
    /// с остальными подписями. Исходный файл не меняется.
    /// </summary>
    public async Task RemoveSignerFromFileAsync(string path)
    {
        if (RequestSignerChoiceAsync is null)
            return;

        var name = System.IO.Path.GetFileName(path);
        IReadOnlyList<CmsExtractor.SignerInfo> signers;
        try
        {
            signers = await Task.Run(() => CmsExtractor.ListSigners(path));
        }
        catch (Exception ex)
        {
            StatusText = $"Не удалось прочитать подпись «{name}»: {ex.Message}";
            return;
        }

        if (signers.Count < 2)
        {
            StatusText = $"«{name}»: подписант один — последнего подписанта исключить нельзя.";
            return;
        }

        var signerId = await RequestSignerChoiceAsync(signers);
        if (signerId is null)
            return;

        IsBusy = true;
        try
        {
            var r = await Task.Run(() => CmsExtractor.RemoveSignerFromFile(path, signerId));
            StatusText = $"Подписант исключён → «{System.IO.Path.GetFileName(r.OutputPath)}», "
                + $"осталось подписантов: {r.SignerCount}. Исходный «{name}» не изменён.";
        }
        catch (Exception ex)
        {
            StatusText = "Не удалось исключить подписанта: " + ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>ПКМ: открыть папку файла.</summary>
    [RelayCommand]
    private void OpenFolder(SignFileItem item)
    {
        try
        {
            var directory = System.IO.Path.GetDirectoryName(item.FilePath) ?? ".";
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(directory)
            {
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            StatusText = "Не удалось открыть папку: " + ex.Message;
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
    private void RemoveFile(SignFileItem item)
    {
        Files.Remove(item);
        if (ApplyCoSignToAll)
            SyncSharedCoSignMode();
    }

    [RelayCommand(CanExecute = nameof(CanClear))]
    private void Clear()
    {
        Files.Clear();
        StatusText = "Список файлов очищен";
    }

    private bool CanClear() => !IsBusy;

    private bool CanSignAll() =>
        !IsBusy && !IsDiscovering && SelectedCertificate is not null && Files.Count > 0;

    /// <summary>
    /// Текст подтверждения перед подписанием: новый файл при уже найденных подписях,
    /// перезапись «документ.sig» без объединения, исключение подписантов.
    /// null — подтверждение не требуется.
    /// </summary>
    internal string? DescribeSignRisks(IReadOnlyList<SignFileItem> files)
    {
        var blocks = new List<string>();
        foreach (var file in files)
        {
            // Копия со штампом подписывается отдельно: найденные подписи оригинала не затрагиваются.
            if (file.SignsStampedCopy)
                continue;
            var createNew = file.SelectedCoSignOption is not { CreateNew: false };
            if (createNew)
            {
                var canonical = file.FilePath + ".sig";
                var others = file.DiscoveredMatches
                    .Where(match => !SignatureDiscovery.SamePath(match.Path, canonical))
                    .ToList();
                if (others.Count > 0)
                {
                    blocks.Add($"«{file.FileName}»: в папке уже есть подходящая подпись "
                        + string.Join(", ", others.Select(match =>
                            $"«{System.IO.Path.GetFileName(match.Path)}» ({match.SignerCount} {SignatureDiscovery.SignerWord(match.SignerCount)})"))
                        + ". Будет создан новый файл «" + System.IO.Path.GetFileName(canonical)
                        + "», эти подписи не изменятся и не будут объединены.");
                }

                if (System.IO.File.Exists(canonical))
                {
                    blocks.Add($"«{file.FileName}»: файл «{System.IO.Path.GetFileName(canonical)}» уже существует "
                        + "и будет перезаписан без объединения. Подписанты из него не сохранятся в новом файле "
                        + "(перед заменой создаётся резервная копия).");
                }
            }

            WarnIfEmbeddedDocumentDropped(file, blocks);

            var inputs = file.PlannedMergeInputs();
            if (inputs.Count == 0)
                continue;
            try
            {
                var document = System.IO.File.ReadAllBytes(file.FilePath);
                var signatures = inputs.Select(System.IO.File.ReadAllBytes).ToList();
                var preview = CmsMerger.MergeForDocument(signatures, document, attach: false, throwIfEmpty: false);
                if (preview.ExcludedSigners.Count > 0)
                {
                    blocks.Add($"«{file.FileName}»: при объединении будут исключены подписанты, "
                        + "чья подпись не соответствует документу: " + string.Join("; ", preview.ExcludedSigners)
                        + ". Они не попадут в файл подписи.");
                }
            }
            catch (Exception e)
            {
                blocks.Add($"«{file.FileName}»: не удалось заранее проверить объединяемые подписи ({e.Message}).");
            }
        }

        if (blocks.Count == 0)
            return null;
        return string.Join("\n\n", blocks) + "\n\nПродолжить?";
    }

    // Прикреплённая подпись хранит копию документа внутри. Откреплённый режим
    // или другая копия документа эту копию затирают — предупреждаем до записи.
    private void WarnIfEmbeddedDocumentDropped(SignFileItem file, List<string> blocks)
    {
        if (file.SignsStampedCopy || file.SelectedCoSignOption is not { CreateNew: false, SignaturePath: { } path })
            return;
        if (!System.IO.File.Exists(path))
            return;
        try
        {
            var embedded = CmsMerger.ExtractContent(System.IO.File.ReadAllBytes(path));
            if (embedded is null)
                return;
            var name = System.IO.Path.GetFileName(path);
            if (IsDetached)
            {
                blocks.Add($"«{file.FileName}»: «{name}» — прикреплённая подпись, внутри лежит копия документа. "
                    + "Откреплённый режим уберёт её из файла (подписанты сохранятся, перед заменой создаётся резервная копия).");
                return;
            }

            var document = System.IO.File.ReadAllBytes(file.FilePath);
            if (!embedded.AsSpan().SequenceEqual(document))
                blocks.Add($"«{file.FileName}»: в «{name}» вложен другой документ. Он будет заменён текущим файлом "
                    + "(перед заменой создаётся резервная копия).");
        }
        catch (Exception e)
        {
            blocks.Add($"«{file.FileName}»: не удалось проверить, есть ли внутри подписи копия документа ({e.Message}).");
        }
    }

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

        // Параметры штампа спрашиваем один раз на весь пакет.
        PdfStamper.StampOptions? stampParameters = null;
        if (UseStamp)
        {
            if (RequestStampOptionsAsync is null)
                return;
            var stampResult = await RequestStampOptionsAsync(true);
            if (stampResult is null)
            {
                StatusText = "Подписание отменено (диалог штампа закрыт).";
                return;
            }

            SaveStampOptions(stampResult);
            stampParameters = stampResult.Options;
        }

        IsBusy = true;

        var signed = 0;
        var failed = 0;

        try
        {
            // МЧД проверяется один раз на пакет — против фактического сертификата;
            // в каталоги документов копируется именно проверенный снимок файлов.
            PowerOfAttorneyService.PoaPackage? poaPackage = null;
            if (Poa is { } poa)
            {
                var poaOptions = CreateVerificationOptions();
                try
                {
                    poaPackage = await Task.Run(() => PowerOfAttorneyService.Prepare(poa, certificate, poaOptions));
                }
                catch (Exception ex)
                {
                    StatusText = "Подписание остановлено — не удалось проверить МЧД: " + ex.Message;
                    return;
                }

                if (poaPackage.Check.State == PowerOfAttorneyService.CheckState.Error)
                {
                    StatusText = "Подписание остановлено — проблема с МЧД: " + poaPackage.Check.Message;
                    return;
                }
                if (poaPackage.Check.State == PowerOfAttorneyService.CheckState.Warning)
                    Log("⚠ МЧД: " + poaPackage.Check.Message);
            }

            var pending = Files.Where(file => file.Status != SignStatus.Signed).ToList();
            var risks = await Task.Run(() => DescribeSignRisks(pending));
            if (risks is not null)
            {
                if (RequestConfirmAsync is null)
                {
                    StatusText = "Подписание остановлено — нужно подтверждение. " + risks;
                    return;
                }

                var confirmed = await RequestConfirmAsync("Подтверждение подписания", risks);
                if (!confirmed)
                {
                    StatusText = "Подписание отменено.";
                    return;
                }
            }

            foreach (var file in pending)
            {
                file.Warning = null;
                file.Status = SignStatus.Signing;
                StatusText = $"Подписание: {file.FileName}";

                try
                {
                    // Task.Run: подпись может блокировать (диалог PIN-кода CSP),
                    // не держим UI-поток.
                    var inputs = file.PlannedMergeInputs();
                    var existing = !file.SignsStampedCopy && file.SelectedCoSignOption is { CreateNew: false, SignaturePath: { } selected }
                        ? selected
                        : null;
                    var extras = inputs.Where(path => existing is null
                        || !SignatureDiscovery.SamePath(path, existing)).ToList();
                    var options = new DocumentSigner.SignOptions
                    {
                        Detached = IsDetached,
                        // Копия со штампом объединяется только со своей прежней подписью, как раньше.
                        MergeWithExisting = existing is not null || (file.SignsStampedCopy && MergeWithExisting),
                        ExistingSignaturePath = existing,
                        ExtraSignatures = extras,
                        Timestamp = UseTimestamp,
                        TsaUrl = TsaUrl,
                        Stamp = UseStamp,
                        StampSignCopy = StampSignCopy,
                        StampWithDate = StampWithDate,
                        StampLogoPath = StampLogoPath,
                        StampParameters = stampParameters,
                        CreateBackup = CreateSignatureBackup,
                        PowerOfAttorney = poaPackage?.Info,
                        PreparedPowerOfAttorney = poaPackage,
                    };
                    var result = await Task.Run(
                        () => _documentSigner.SignFileAsync(file.FilePath, certificate, options));
                    file.SignaturePath = result.SignaturePath;
                    file.SignerCount = result.SignerCount;
                    file.PreviousSignerCount = result.PreviousSignerCount;
                    file.AppendedToExisting = result.AppendedToExisting;

                    if (result.ExcludedSigners.Count > 0)
                        file.Warning = "Внимание: исключены подписанты, подпись которых не соответствует документу: "
                            + string.Join("; ", result.ExcludedSigners);
                    file.Message = result.UnverifiedSigners.Count > 0
                        ? "не удалось проверить: " + string.Join("; ", result.UnverifiedSigners)
                        : null;

                    file.Status = SignStatus.Signed;
                    signed++;
                    Log($"  [OK] {file.FileName} → {file.StatusDisplay}"
                        + (result.BackupPath is null
                            ? ""
                            : $". Резервная копия: {System.IO.Path.GetFileName(result.BackupPath)}")
                        + (result.StampedCopyPath is null
                            ? ""
                            : $"; копия со штампом (без подписи): {System.IO.Path.GetFileName(result.StampedCopyPath)}"));
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
        catch (Exception ex)
        {
            StatusText = "Подписание остановлено: " + ex.Message;
            return;
        }
        finally
        {
            IsBusy = false;
        }

        StatusText = failed == 0
            ? $"Готово. Подписано файлов: {signed}"
            : $"Подписано: {signed}, с ошибками: {failed}";

        // Файлы подписи изменились: обновляем варианты, чтобы следующее соподписание
        // (например, после смены сертификата) дописывало подпись в получившийся файл.
        var processed = Files.Where(file => file.Status == SignStatus.Signed).ToList();
        await DiscoverAsync(processed, Array.Empty<string>(), processed);
    }
}
