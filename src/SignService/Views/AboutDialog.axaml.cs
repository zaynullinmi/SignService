using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using Avalonia.Controls;
using SignService.Services;

namespace SignService.Views;

/// <summary>
/// Окно «О программе»: версия, автор, история версий (встроенный CHANGELOG),
/// проверка и установка обновлений через GitHub Releases.
/// </summary>
public partial class AboutDialog : Window
{
    private readonly UpdateService _updateService = new();
    private readonly AppSettings _settings;
    private UpdateService.UpdateInfo? _available;

    public AboutDialog()
        : this(AppSettings.Load())
    {
    }

    public AboutDialog(AppSettings settings)
    {
        InitializeComponent();
        _settings = settings;

        VersionText.Text = $"Версия {UpdateService.CurrentVersion}";
        ChangelogText.Text = LoadChangelog();
        AutoCheckBox.IsChecked = _settings.CheckUpdatesOnStart;

        CloseButton.Click += (_, _) => Close();
        ProjectLinkButton.Click += (_, _) => OpenUrl("https://github.com/zaynullinmi/SignService");
        CheckUpdateButton.Click += async (_, _) => await CheckAsync();
        InstallUpdateButton.Click += async (_, _) => await InstallAsync();
        AutoCheckBox.IsCheckedChanged += (_, _) =>
        {
            _settings.CheckUpdatesOnStart = AutoCheckBox.IsChecked == true;
            _settings.Save();
        };
    }

    private static string LoadChangelog()
    {
        try
        {
            using var stream = Assembly.GetExecutingAssembly()
                .GetManifestResourceStream("SignService.CHANGELOG.md");
            if (stream is null)
                return "(история версий недоступна)";
            using var reader = new StreamReader(stream);
            return reader.ReadToEnd();
        }
        catch (Exception e)
        {
            return "(не удалось загрузить историю версий: " + e.Message + ")";
        }
    }

    private async System.Threading.Tasks.Task CheckAsync()
    {
        CheckUpdateButton.IsEnabled = false;
        UpdateStatusText.Text = "Проверка…";
        try
        {
            _available = await _updateService.CheckForUpdateAsync();
            if (_available is null)
            {
                UpdateStatusText.Text = $"У вас последняя версия ({UpdateService.CurrentVersion}).";
            }
            else
            {
                UpdateStatusText.Text = $"Доступна новая версия {_available.Version}.";
                InstallUpdateButton.IsVisible = _available.ExeDownloadUrl is not null && OperatingSystem.IsWindows();
                if (!InstallUpdateButton.IsVisible)
                    UpdateStatusText.Text += " Скачайте её со страницы проекта.";
            }
        }
        catch (Exception e)
        {
            UpdateStatusText.Text = "Не удалось проверить обновления: " + e.Message;
        }
        finally
        {
            CheckUpdateButton.IsEnabled = true;
        }
    }

    private async System.Threading.Tasks.Task InstallAsync()
    {
        if (_available is null)
            return;

        InstallUpdateButton.IsEnabled = false;
        UpdateStatusText.Text = $"Скачивание версии {_available.Version}…";
        try
        {
            var downloaded = await _updateService.DownloadAsync(_available);
            UpdateStatusText.Text = "Установка: программа перезапустится…";
            _updateService.ApplyAndRestart(downloaded);
            // Закрываем всё приложение — скрипт заменит exe и запустит новую версию.
            if (Avalonia.Application.Current?.ApplicationLifetime
                is Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop)
                desktop.Shutdown();
        }
        catch (Exception e)
        {
            UpdateStatusText.Text = "Не удалось установить обновление: " + e.Message;
            InstallUpdateButton.IsEnabled = true;
        }
    }

    private static void OpenUrl(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception)
        {
            // не удалось открыть браузер — не критично
        }
    }
}
