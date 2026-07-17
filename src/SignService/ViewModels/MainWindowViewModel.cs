using System;
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

    /// <summary>Добавляет файлы в очередь, пропуская дубликаты и файлы подписей.</summary>
    public void AddFiles(params string[] filePaths)
    {
        var added = 0;
        foreach (var path in filePaths)
        {
            if (string.IsNullOrWhiteSpace(path) || !System.IO.File.Exists(path))
                continue;
            if (path.EndsWith(".sig", StringComparison.OrdinalIgnoreCase))
                continue;
            if (Files.Any(f => string.Equals(f.FilePath, path, StringComparison.OrdinalIgnoreCase)))
                continue;

            Files.Add(new SignFileItem(path));
            added++;
        }

        if (added > 0)
            StatusText = $"Добавлено файлов: {added}. Всего в очереди: {Files.Count}";
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
                    // Task.Run: ComputeSignature может блокировать (диалог PIN-кода CSP),
                    // не держим UI-поток.
                    file.SignaturePath = await Task.Run(
                        () => _documentSigner.SignFileAsync(file.FilePath, certificate, IsDetached));
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
