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

        DataContextChanged += (_, _) =>
        {
            if (DataContext is MainWindowViewModel vm)
                vm.BrowseRequested += async (_, _) => await BrowseFilesAsync(vm);
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
}
