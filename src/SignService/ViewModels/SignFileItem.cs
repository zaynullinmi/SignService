using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;

namespace SignService.ViewModels;

public enum SignStatus
{
    Pending,
    Signing,
    Signed,
    Failed,
}

/// <summary>
/// Файл в очереди на подписание.
/// </summary>
public partial class SignFileItem : ObservableObject
{
    public SignFileItem(string filePath)
    {
        FilePath = filePath;
        FileName = Path.GetFileName(filePath);

        var info = new FileInfo(filePath);
        SizeDisplay = info.Exists ? FormatSize(info.Length) : "—";
    }

    public string FilePath { get; }

    public string FileName { get; }

    public string SizeDisplay { get; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusDisplay))]
    private SignStatus _status = SignStatus.Pending;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusDisplay))]
    private string? _message;

    /// <summary>Путь к созданному файлу подписи (.sig).</summary>
    [ObservableProperty]
    private string? _signaturePath;

    /// <summary>Число подписантов в созданном .sig (после соподписания может быть больше 1).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusDisplay))]
    private int _signerCount;

    private readonly List<string> _extraSignatures = new();

    /// <summary>Приложенные подписи других лиц для объединения (пути к .sig).</summary>
    public IReadOnlyList<string> ExtraSignatures => _extraSignatures;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasExtra))]
    [NotifyPropertyChangedFor(nameof(ExtraDisplay))]
    private int _extraCount;

    public bool HasExtra => ExtraCount > 0;

    public string ExtraDisplay => $"＋ подписей: {ExtraCount}";

    /// <summary>Прикладывает файлы подписей других лиц (дубликаты пропускаются).</summary>
    public int AttachSignatures(IEnumerable<string> sigPaths)
    {
        var added = 0;
        foreach (var path in sigPaths)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                continue;
            if (_extraSignatures.Any(p => string.Equals(p, path, StringComparison.OrdinalIgnoreCase)))
                continue;
            _extraSignatures.Add(path);
            added++;
        }

        ExtraCount = _extraSignatures.Count;
        return added;
    }

    public string StatusDisplay => Status switch
    {
        SignStatus.Pending => "Ожидает",
        SignStatus.Signing => "Подписывается…",
        SignStatus.Signed when SignerCount > 1 =>
            $"Подписан (подписантов: {SignerCount}) → {Path.GetFileName(SignaturePath)}{SignedNote}",
        SignStatus.Signed => $"Подписан → {Path.GetFileName(SignaturePath)}{SignedNote}",
        SignStatus.Failed => $"Ошибка: {Message}",
        _ => string.Empty,
    };

    private string SignedNote => string.IsNullOrEmpty(Message) ? string.Empty : $" ⚠ {Message}";

    private static string FormatSize(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} Б",
        < 1024 * 1024 => $"{bytes / 1024.0:0.#} КБ",
        < 1024 * 1024 * 1024 => $"{bytes / (1024.0 * 1024):0.#} МБ",
        _ => $"{bytes / (1024.0 * 1024 * 1024):0.##} ГБ",
    };
}
