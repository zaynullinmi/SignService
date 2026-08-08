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
        _initializing = false;

        Files.CollectionChanged += (_, _) => SignAllCommand.NotifyCanExecuteChanged();
        RefreshCertificates();
    }

    public ObservableCollection<CertificateItem> Certificates { get; } = new();

    public ObservableCollection<SignFileItem> Files { get; } = new();

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SignAllCommand))]
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

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SignAllCommand))]
    [NotifyCanExecuteChangedFor(nameof(BrowseCommand))]
    [NotifyCanExecuteChangedFor(nameof(ClearCommand))]
    private bool _isBusy;

    [ObservableProperty]
    private string _statusText = "Перетащите файлы в окно или добавьте их через «Обзор…»";

    /// <summary>
    /// Запрос диалога выбора файлов; обрабатывается в MainWindow,
    /// т.к. StorageProvider доступен только на уровне окна.
    /// </summary>
    public event EventHandler? BrowseRequested;

    /// <summary>Запрос диалога выбора .sig других лиц для объединения с подписью файла.</summary>
    public event EventHandler<SignFileItem>? AttachSignaturesRequested;

    /// <summary>Запрос диалога выбора контейнеров для извлечения.</summary>
    public event EventHandler? ExtractRequested;

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
            return;
        }

        SelectedCertificate =
            Certificates.FirstOrDefault(c => c.Thumbprint == previous) ?? Certificates.FirstOrDefault();

        StatusText = Certificates.Count == 0
            ? "В хранилище не найдено сертификатов с закрытым ключом"
            : $"Найдено сертификатов: {Certificates.Count}";
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
        var certificate = SelectedCertificate!.Certificate;
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
                    var result = await Task.Run(
                        () => _documentSigner.SignFileAsync(
                            file.FilePath, certificate, IsDetached,
                            MergeWithExisting, file.ExtraSignatures));
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
                }
                catch (Exception ex)
                {
                    file.Message = ex.Message;
                    file.Status = SignStatus.Failed;
                    failed++;
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
