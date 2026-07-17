using System.IO;
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

    public string StatusDisplay => Status switch
    {
        SignStatus.Pending => "Ожидает",
        SignStatus.Signing => "Подписывается…",
        SignStatus.Signed => $"Подписан → {Path.GetFileName(SignaturePath)}",
        SignStatus.Failed => $"Ошибка: {Message}",
        _ => string.Empty,
    };

    private static string FormatSize(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} Б",
        < 1024 * 1024 => $"{bytes / 1024.0:0.#} КБ",
        < 1024 * 1024 * 1024 => $"{bytes / (1024.0 * 1024):0.#} МБ",
        _ => $"{bytes / (1024.0 * 1024 * 1024):0.##} ГБ",
    };
}
