using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Platform.Storage;
using SignService.Services;

namespace SignService.Views;

public partial class VerificationDialog : Window
{
    private readonly AppSettings _settings;
    private string? _signaturePath;
    private string? _documentPath;
    private List<string> _evidencePaths = new();
    private CancellationTokenSource? _cancellation;

    public VerificationDialog() : this(new AppSettings()) { }

    public VerificationDialog(AppSettings settings)
    {
        InitializeComponent();
        _settings = settings;
        NetworkCheckBox.IsChecked = settings.VerificationAllowNetwork;
        UpdatePaths();
        SignatureButton.Click += async (_, _) =>
        {
            var selected = (await Pick("Файл электронной подписи", "Подписи CMS", "*.sig", "*.p7s", "*.p7m")).FirstOrDefault();
            if (selected is null) return;
            _signaturePath = selected;
            var nearby = _signaturePath.EndsWith(".sig", StringComparison.OrdinalIgnoreCase) || _signaturePath.EndsWith(".p7s", StringComparison.OrdinalIgnoreCase)
                ? _signaturePath[..^4] : "";
            _documentPath = File.Exists(nearby) ? nearby : null;
            Reset();
        };
        DocumentButton.Click += async (_, _) =>
        {
            var selected = (await Pick("Исходный документ", "Все файлы", "*")).FirstOrDefault();
            if (selected is not null) { _documentPath = selected; Reset(); }
        };
        ClearDocumentButton.Click += (_, _) => { _documentPath = null; Reset(); };
        RootsButton.Click += async (_, _) =>
        {
            var paths = await Pick("Корни доверенных УЦ (дополнительно к хранилищу ОС)", "Сертификаты", "*.cer", "*.crt", "*.pem", multiple: true);
            if (paths.Count == 0) return;
            _settings.VerificationTrustedRootPaths = paths;
            _settings.Save();
            Reset();
        };
        ClearRootsButton.Click += (_, _) => { _settings.VerificationTrustedRootPaths.Clear(); _settings.Save(); Reset(); };
        EvidenceButton.Click += async (_, _) =>
        {
            _evidencePaths = await Pick("Подписанные CRL или ответы OCSP", "CRL/OCSP", "*.crl", "*.ocsp", "*.der", multiple: true);
            Reset();
        };
        NetworkCheckBox.IsCheckedChanged += (_, _) =>
        {
            _settings.VerificationAllowNetwork = NetworkCheckBox.IsChecked == true;
            _settings.Save(); Reset();
        };
        VerifyButton.Click += async (_, _) => await VerifyAsync();
        CancelButton.Click += (_, _) => _cancellation?.Cancel();
        CopyButton.Click += async (_, _) =>
        {
            if (Clipboard is not null && !string.IsNullOrEmpty(ReportBox.Text))
                await Clipboard.SetTextAsync(ReportBox.Text);
        };
        SaveButton.Click += async (_, _) =>
        {
            if (string.IsNullOrEmpty(ReportBox.Text)) return;
            var target = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
                { Title = "Сохранить отчёт проверки", SuggestedFileName = "Проверка ЭЦП.txt", DefaultExtension = "txt" });
            var path = target?.TryGetLocalPath();
            if (path is null) return;
            try { await AtomicFile.WriteAsync(path, Encoding.UTF8.GetBytes(ReportBox.Text)); }
            catch (Exception e) { StatusText.Text = "Не удалось сохранить отчёт: " + e.Message; }
        };
        CloseButton.Click += (_, _) => Close();
        Closing += (_, _) => _cancellation?.Cancel();
    }

    private async Task VerifyAsync()
    {
        if (_signaturePath is null) { StatusText.Text = "Сначала выберите файл подписи."; return; }
        using var cancellation = new CancellationTokenSource();
        _cancellation = cancellation;
        OptionsPanel.IsEnabled = VerifyButton.IsEnabled = CopyButton.IsEnabled = SaveButton.IsEnabled = false;
        CancelButton.IsEnabled = true;
        ReportBox.Text = "";
        StatusText.Text = "Проверяются подписи, сертификаты и метки времени…";
        try
        {
            var signature = await File.ReadAllBytesAsync(_signaturePath, cancellation.Token);
            var document = _documentPath is null ? null : await File.ReadAllBytesAsync(_documentPath, cancellation.Token);
            var roots = _settings.VerificationTrustedRootPaths.Select(File.ReadAllBytes).ToArray();
            var crls = _evidencePaths.Where(p => p.EndsWith(".crl", StringComparison.OrdinalIgnoreCase)).Select(File.ReadAllBytes).ToArray();
            var ocsp = _evidencePaths.Where(p => !p.EndsWith(".crl", StringComparison.OrdinalIgnoreCase)).Select(File.ReadAllBytes).ToArray();
            var result = await SignatureVerifier.VerifyAsync(signature, document, new VerificationOptions
                { AllowNetwork = NetworkCheckBox.IsChecked == true, TrustedRoots = roots, Crls = crls, OcspResponses = ocsp }, cancellation.Token);
            ReportBox.Text = $"Отчёт создан: {DateTimeOffset.Now:dd.MM.yyyy HH:mm:ss zzz}\n\n"
                + result.ToReport(_signaturePath, _documentPath);
            StatusText.Text = result.CryptographicallyValid ? "Криптографическая проверка пройдена. Доверие и отзыв смотрите в отчёте."
                : "Проверка завершена: есть ошибки или непроверенные подписи. Подробности в отчёте.";
        }
        catch (OperationCanceledException) { StatusText.Text = "Проверка отменена."; }
        catch (Exception e) { StatusText.Text = "Проверка не выполнена: " + e.Message; }
        finally
        {
            _cancellation = null;
            OptionsPanel.IsEnabled = VerifyButton.IsEnabled = CopyButton.IsEnabled = SaveButton.IsEnabled = true;
            CancelButton.IsEnabled = false;
        }
    }

    private void Reset() { ReportBox.Text = ""; StatusText.Text = "Параметры изменены. Нажмите «Проверить»."; UpdatePaths(); }

    private void UpdatePaths()
    {
        SignaturePathText.Text = _signaturePath ?? "не выбрана";
        DocumentPathText.Text = _documentPath ?? "не выбран; для прикреплённой подписи будет взят из контейнера";
        RootsText.Text = "Доверие: корни из хранилища ОС + выбранные корни: " + _settings.VerificationTrustedRootPaths.Count;
        ToolTip.SetTip(RootsText, string.Join(Environment.NewLine, _settings.VerificationTrustedRootPaths));
        EvidenceText.Text = "Файлов CRL/OCSP: " + _evidencePaths.Count;
    }

    private async Task<List<string>> Pick(string title, string type, string pattern1,
        string? pattern2 = null, string? pattern3 = null, bool multiple = false)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = title, AllowMultiple = multiple,
            FileTypeFilter = new[] { new FilePickerFileType(type)
                { Patterns = new[] { pattern1, pattern2, pattern3 }.OfType<string>().ToArray() }, FilePickerFileTypes.All },
        });
        return files.Select(f => f.TryGetLocalPath()).OfType<string>().ToList();
    }
}
