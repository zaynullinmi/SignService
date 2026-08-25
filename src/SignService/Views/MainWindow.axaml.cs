using System.Collections.Generic;
using System.IO;
using System.Linq;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using SignService.ViewModels;

namespace SignService.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();

        AddHandler(DragDrop.DragOverEvent, OnDragOver);
        AddHandler(DragDrop.DragLeaveEvent, OnDragLeave);
        AddHandler(DragDrop.DropEvent, OnDrop);

        AboutButton.Click += async (_, _) =>
        {
            var settings = (DataContext as MainWindowViewModel)?.Settings
                ?? SignService.Services.AppSettings.Load();
            await new AboutDialog(settings).ShowDialog(this);
        };

        SettingsButton.Click += async (_, _) =>
        {
            if (DataContext is MainWindowViewModel vm)
                await new SettingsDialog(vm).ShowDialog(this);
        };

        DataContextChanged += (_, _) =>
        {
            if (DataContext is MainWindowViewModel vm)
            {
                vm.BrowseRequested += async (_, _) => await BrowseFilesAsync(vm);
                vm.AttachSignaturesRequested += async (_, item) => await BrowseSignaturesAsync(item);
                vm.ExtractRequested += async (_, _) => await BrowseContainersAsync(vm);
                vm.PickLogoRequested += async (_, _) => await BrowseLogoAsync(vm);
                vm.MergeFilesRequested += async (_, _) => await BrowseMergeFilesAsync(vm);
                vm.StampOnlyRequested += async (_, _) => await BrowseStampOnlyAsync(vm);
                vm.BuildContainerRequested += async (_, _) => await BrowseBuildContainerAsync(vm);
                vm.AddPoaRequested += async (_, _) => await BrowsePoaAsync(vm);
                vm.VerifyFileRequested += async (_, _) => await BrowseVerifyAsync(vm);
                vm.RequestStampOptionsAsync = async showSignCopy =>
                    await new StampOptionsDialog(vm.BuildInitialStampOptions(), vm.StampSignCopy, showSignCopy)
                        .ShowDialog<StampOptionsDialog.Result?>(this);
                vm.ShowSignersReport = text => _ = new SignersDialog(text).ShowDialog(this);
                vm.PropertyChanged += (_, args) =>
                {
                    // автопрокрутка лога вниз
                    if (args.PropertyName == nameof(MainWindowViewModel.LogText))
                        LogBox.CaretIndex = int.MaxValue;
                };
                vm.RequestPasswordAsync = async (title, message, warning, confirm) =>
                    await new PasswordDialog(message, warning, confirm) { Title = title }
                        .ShowDialog<string?>(this);
                vm.RequestConfirmAsync = async (title, message) =>
                    await new ConfirmDialog(title, message).ShowDialog<bool>(this);
            }
        };
    }

    private MainWindowViewModel? ViewModel => DataContext as MainWindowViewModel;

    private void OnDragOver(object? sender, DragEventArgs e)
    {
        e.DragEffects = e.DataTransfer.Contains(DataFormat.File)
            ? DragDropEffects.Copy
            : DragDropEffects.None;

        DropZone.Classes.Set("dragover", e.DragEffects != DragDropEffects.None);
        e.Handled = true;
    }

    private void OnDragLeave(object? sender, RoutedEventArgs e)
    {
        DropZone.Classes.Set("dragover", false);
    }

    private void OnDrop(object? sender, DragEventArgs e)
    {
        DropZone.Classes.Set("dragover", false);

        if (ViewModel is not { } vm || e.DataTransfer.TryGetFiles() is not { } items)
            return;

        vm.AddFiles(ExpandToFilePaths(items).ToArray());
        e.Handled = true;
    }

    /// <summary>
    /// Разворачивает перетащенные элементы в пути к файлам:
    /// для папок берутся все файлы из них (рекурсивно).
    /// </summary>
    private static IEnumerable<string> ExpandToFilePaths(IEnumerable<IStorageItem> items)
    {
        foreach (var item in items)
        {
            var path = item.TryGetLocalPath();
            if (path is null)
                continue;

            if (item is IStorageFolder && Directory.Exists(path))
            {
                foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
                    yield return file;
            }
            else if (File.Exists(path))
            {
                yield return path;
            }
        }
    }

    private async System.Threading.Tasks.Task BrowseFilesAsync(MainWindowViewModel vm)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Выберите файлы для подписания",
            AllowMultiple = true,
        });

        vm.AddFiles(files
            .Select(f => f.TryGetLocalPath())
            .Where(p => p is not null)
            .Select(p => p!)
            .ToArray());
    }

    private async System.Threading.Tasks.Task BrowseSignaturesAsync(SignFileItem item)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = $"Подписи других лиц для объединения — {item.FileName}",
            AllowMultiple = true,
            FileTypeFilter = new[]
            {
                new FilePickerFileType("Подписи CMS (*.sig, *.p7s)") { Patterns = new[] { "*.sig", "*.p7s" } },
                FilePickerFileTypes.All,
            },
        });

        var added = item.AttachSignatures(files
            .Select(f => f.TryGetLocalPath())
            .Where(p => p is not null)
            .Select(p => p!)
            .ToList());

        if (added > 0 && DataContext is MainWindowViewModel vm)
            vm.StatusText = $"Приложено подписей к «{item.FileName}»: {added} (всего: {item.ExtraCount})";
    }

    private async System.Threading.Tasks.Task BrowseLogoAsync(MainWindowViewModel vm)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Логотип организации для штампа",
            AllowMultiple = false,
            FileTypeFilter = new[]
            {
                new FilePickerFileType("Изображения (*.png, *.jpg)")
                {
                    Patterns = new[] { "*.png", "*.jpg", "*.jpeg" },
                },
            },
        });

        var path = files.FirstOrDefault()?.TryGetLocalPath();
        if (path is not null)
            vm.StampLogoPath = path;
    }

    private async System.Threading.Tasks.Task BrowseMergeFilesAsync(MainWindowViewModel vm)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Выберите файлы подписей для объединения (не менее двух)",
            AllowMultiple = true,
            FileTypeFilter = new[]
            {
                new FilePickerFileType("Подписи CMS (*.sig, *.p7s, *.p7m)")
                {
                    Patterns = new[] { "*.sig", "*.p7s", "*.p7m" },
                },
                FilePickerFileTypes.All,
            },
        });

        await vm.MergeSignatureFilesAsync(files
            .Select(f => f.TryGetLocalPath())
            .Where(p => p is not null)
            .Select(p => p!)
            .ToList());
    }

    private async System.Threading.Tasks.Task BrowseStampOnlyAsync(MainWindowViewModel vm)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "PDF-документы для штампа (без подписания)",
            AllowMultiple = true,
            FileTypeFilter = new[]
            {
                new FilePickerFileType("Документы PDF (*.pdf)") { Patterns = new[] { "*.pdf" } },
            },
        });

        var paths = files
            .Select(f => f.TryGetLocalPath())
            .Where(p => p is not null)
            .Select(p => p!)
            .ToList();
        if (paths.Count == 0)
            return;

        var options = await new StampOptionsDialog(vm.BuildInitialStampOptions(), vm.StampSignCopy, showSignCopy: false)
            .ShowDialog<StampOptionsDialog.Result?>(this);
        if (options is null)
            return;

        vm.SaveStampOptions(options);
        await vm.StampWithoutSigningAsync(paths, options.Options);
    }

    private async System.Threading.Tasks.Task BrowseVerifyAsync(MainWindowViewModel vm)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Файл подписи для проверки (документ ищется рядом по имени)",
            AllowMultiple = false,
            FileTypeFilter = new[]
            {
                new FilePickerFileType("Подписи CMS (*.sig, *.p7s, *.p7m)")
                {
                    Patterns = new[] { "*.sig", "*.p7s", "*.p7m" },
                },
                FilePickerFileTypes.All,
            },
        });

        if (files.FirstOrDefault()?.TryGetLocalPath() is { } path)
            await vm.VerifySignatureFileAsync(path);
    }

    private async System.Threading.Tasks.Task BrowsePoaAsync(MainWindowViewModel vm)
    {
        var xmlFiles = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Файл машиночитаемой доверенности (МЧД) — XML",
            AllowMultiple = false,
            FileTypeFilter = new[]
            {
                new FilePickerFileType("Доверенность МЧД (*.xml)") { Patterns = new[] { "*.xml" } },
                FilePickerFileTypes.All,
            },
        });

        var xmlPath = xmlFiles.FirstOrDefault()?.TryGetLocalPath();
        if (xmlPath is null)
            return;

        // Подпись руководителя: «имя.xml.sig» рядом подхватывается автоматически.
        var sigPath = xmlPath + ".sig";
        if (!File.Exists(sigPath))
        {
            var sigFiles = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Подпись руководителя для МЧД — SIG",
                AllowMultiple = false,
                FileTypeFilter = new[]
                {
                    new FilePickerFileType("Подпись (*.sig)") { Patterns = new[] { "*.sig" } },
                    FilePickerFileTypes.All,
                },
            });

            sigPath = sigFiles.FirstOrDefault()?.TryGetLocalPath();
            if (sigPath is null)
                return;
        }

        vm.SetPoa(xmlPath, sigPath);
    }

    private async System.Threading.Tasks.Task BrowseBuildContainerAsync(MainWindowViewModel vm)
    {
        var docs = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Документ для сборки криптоконтейнера",
            AllowMultiple = false,
        });

        var documentPath = docs.FirstOrDefault()?.TryGetLocalPath();
        if (documentPath is null)
            return;

        // Подписи: «документ.sig» рядом, иначе — выбрать вручную.
        IReadOnlyList<string>? signaturePaths = null;
        if (!File.Exists(documentPath + ".sig"))
        {
            var sigs = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = $"Подписи для контейнера — {Path.GetFileName(documentPath)}",
                AllowMultiple = true,
                FileTypeFilter = new[]
                {
                    new FilePickerFileType("Подписи CMS (*.sig, *.p7s)") { Patterns = new[] { "*.sig", "*.p7s" } },
                    FilePickerFileTypes.All,
                },
            });

            signaturePaths = sigs
                .Select(f => f.TryGetLocalPath())
                .Where(p => p is not null)
                .Select(p => p!)
                .ToList();
            if (signaturePaths.Count == 0)
                return;
        }

        await vm.BuildContainerAsync(documentPath, signaturePaths);
    }

    private async System.Threading.Tasks.Task BrowseContainersAsync(MainWindowViewModel vm)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Выберите криптоконтейнеры для извлечения",
            AllowMultiple = true,
            FileTypeFilter = new[]
            {
                new FilePickerFileType("Подписи CMS (*.sig, *.p7s, *.p7m)")
                {
                    Patterns = new[] { "*.sig", "*.p7s", "*.p7m" },
                },
                FilePickerFileTypes.All,
            },
        });

        await vm.ExtractContainersAsync(files
            .Select(f => f.TryGetLocalPath())
            .Where(p => p is not null)
            .Select(p => p!)
            .ToList());
    }
}
