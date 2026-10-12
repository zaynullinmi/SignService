using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using SignService.Services;

namespace SignService.ViewModels;

public enum SignStatus
{
    Pending,
    Signing,
    Signed,
    Failed,
}

/// <summary>Вариант в списке файла: добавить подпись в найденный .sig или создать новый.</summary>
public sealed class CoSignOption
{
    public CoSignOption(string? signaturePath, int signerCount)
    {
        SignaturePath = signaturePath;
        SignerCount = signerCount;
        Label = signaturePath is null
            ? "Создать новую подпись"
            : $"Добавить к «{Path.GetFileName(signaturePath)}» ({signerCount} {SignatureDiscovery.SignerWord(signerCount)})";
    }

    /// <summary>null — создать «документ.sig», не объединяя с найденными файлами.</summary>
    public string? SignaturePath { get; }

    public int SignerCount { get; }

    public string Label { get; }

    public bool CreateNew => SignaturePath is null;

    public override string ToString() => Label;
}

/// <summary>
/// Файл в очереди на подписание.
/// </summary>
public partial class SignFileItem : ObservableObject
{
    private readonly List<string> _extraSignatures = new();
    private IReadOnlyList<SignatureDiscovery.SignatureMatch> _discovered = Array.Empty<SignatureDiscovery.SignatureMatch>();
    private bool _adjustingSelection;
    private bool _mentionBackup;
    private bool _followingShared;
    private bool _sharedWantsAdd;
    private int _unionCount;
    private string _planText = "будет создан новый файл подписи";

    public SignFileItem(string filePath)
    {
        FilePath = filePath;
        FileName = Path.GetFileName(filePath);

        var info = new FileInfo(filePath);
        SizeDisplay = info.Exists ? FormatSize(info.Length) : "—";
        CoSignOptions.Add(new CoSignOption(null, 0));
        _adjustingSelection = true;
        SelectedCoSignOption = CoSignOptions[0];
        _adjustingSelection = false;
    }

    public string FilePath { get; }

    /// <summary>
    /// Модель окна, в очереди которой стоит файл: из контекстного меню файла
    /// (всплывающее окно вне дерева элементов) команды доступны только через неё.
    /// </summary>
    public MainWindowViewModel? Owner { get; init; }

    public string FileName { get; }

    public string SizeDisplay { get; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusDisplay))]
    [NotifyPropertyChangedFor(nameof(WarningDisplay))]
    [NotifyPropertyChangedFor(nameof(HasWarning))]
    [NotifyPropertyChangedFor(nameof(CanChooseCoSign))]
    private SignStatus _status = SignStatus.Pending;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusDisplay))]
    private string? _message;

    /// <summary>Предупреждение об исключённых при объединении подписантах — отдельной строкой.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(WarningDisplay))]
    [NotifyPropertyChangedFor(nameof(HasWarning))]
    private string? _warning;

    /// <summary>Путь к созданному файлу подписи (.sig).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusDisplay))]
    private string? _signaturePath;

    /// <summary>Число подписантов в созданном .sig (после соподписания может быть больше 1).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusDisplay))]
    private int _signerCount;

    /// <summary>Сколько подписантов было в файле, к которому добавили подпись.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusDisplay))]
    private int _previousSignerCount;

    /// <summary>true — подпись дописана в уже существовавший файл, false — создан новый.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusDisplay))]
    private bool _appendedToExisting;

    /// <summary>Идёт поиск подписей документа (в фоне, после добавления в очередь).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusDisplay))]
    [NotifyPropertyChangedFor(nameof(CanChooseCoSign))]
    private bool _isDiscovering;

    /// <summary>
    /// Подписывается копия со штампом (режим «подписывать копию»): найденные подписи
    /// оригинала к ней не относятся — объединяются только приложенные.
    /// </summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanChooseCoSign))]
    private bool _signsStampedCopy;

    partial void OnSignsStampedCopyChanged(bool value) => UpdatePlan();

    /// <summary>Приложенные подписи других лиц для объединения (пути к .sig).</summary>
    public IReadOnlyList<string> ExtraSignatures => _extraSignatures;

    /// <summary>Подписи из папки документа, относящиеся к нему (и «документ.sig»).</summary>
    public IReadOnlyList<SignatureDiscovery.SignatureMatch> DiscoveredMatches => _discovered;

    /// <summary>Пользователь сам выбрал режим для этого файла — общий переключатель его не сбрасывает, пока не переключат режим целиком.</summary>
    public bool CoSignPinned { get; private set; }

    public ObservableCollection<CoSignOption> CoSignOptions { get; } = new();

    [ObservableProperty]
    private CoSignOption? _selectedCoSignOption;

    /// <summary>Режим задаёт первый файл («Применить ко всем») — список в этой строке только для чтения.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanChooseCoSign))]
    private bool _coSignLocked;

    /// <summary>Общий режим «добавить» для этого файла невозможен.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(WarningDisplay))]
    [NotifyPropertyChangedFor(nameof(HasWarning))]
    private bool _sharedAddUnavailable;

    /// <summary>Режим можно менять, пока файл ждёт подписания и программа не занята.</summary>
    public bool CanChooseCoSign => Status is SignStatus.Pending or SignStatus.Failed && !IsDiscovering && !SignsStampedCopy
        && !CoSignLocked && Owner?.IsBusy != true;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasExtra))]
    [NotifyPropertyChangedFor(nameof(ExtraDisplay))]
    private int _extraCount;

    public bool HasExtra => ExtraCount > 0;

    public string ExtraDisplay => $"＋ подписей: {ExtraCount}";

    public bool HasWarning => !string.IsNullOrEmpty(WarningDisplay);

    public string? WarningDisplay => !string.IsNullOrEmpty(Warning) ? Warning : DiscoveryWarning();

    /// <summary>Применяет результат поиска подписей (вызывается в потоке интерфейса).</summary>
    public void ApplyDiscovery(SignatureDiscovery.DocumentDiscovery discovery, bool preferAdd)
    {
        _discovered = discovery.FolderMatches;
        _unionCount = discovery.FolderSignerCount;

        var previous = SelectedCoSignOption?.SignaturePath;
        // Выбор для уже выполненного подписания исчерпан: дальше — общий режим.
        if (Status == SignStatus.Signed)
            CoSignPinned = false;
        var pinned = CoSignPinned;
        _adjustingSelection = true;
        CoSignOptions.Clear();
        foreach (var match in _discovered)
            CoSignOptions.Add(new CoSignOption(match.Path, match.SignerCount));
        CoSignOptions.Add(new CoSignOption(null, 0));

        if (_followingShared)
            ApplySharedSelection();
        else if (pinned && previous is null)
            SelectedCoSignOption = CoSignOptions.Last(option => option.CreateNew);
        else if (pinned)
            SelectedCoSignOption = CoSignOptions.FirstOrDefault(option =>
                    option.SignaturePath is not null && SignatureDiscovery.SamePath(option.SignaturePath, previous!))
                ?? CoSignOptions.FirstOrDefault(option => !option.CreateNew)
                ?? CoSignOptions.Last();
        else
            SelectedCoSignOption = preferAdd
                ? CoSignOptions.FirstOrDefault(option => !option.CreateNew) ?? CoSignOptions.Last()
                : CoSignOptions.Last(option => option.CreateNew);
        _adjustingSelection = false;
        UpdatePlan();
    }

    /// <summary>Упоминать ли в плане, что перед потерей данных сохранится .bak.</summary>
    public void SetBackupMention(bool enabled)
    {
        if (_mentionBackup == enabled)
            return;
        _mentionBackup = enabled;
        UpdatePlan();
    }

    /// <summary>
    /// Повторяет режим первого файла. Если добавить не к чему, остаётся «Создать новую»
    /// и строка явно об этом говорит.
    /// </summary>
    public void FollowSharedMode(bool addToExisting)
    {
        _followingShared = true;
        _sharedWantsAdd = addToExisting;
        CoSignPinned = false;
        _adjustingSelection = true;
        ApplySharedSelection();
        _adjustingSelection = false;
        UpdatePlan();
    }

    /// <summary>Снимает общий режим, не меняя уже выбранный пункт.</summary>
    public void StopFollowingSharedMode()
    {
        _followingShared = false;
        if (!SharedAddUnavailable)
            return;
        SharedAddUnavailable = false;
        UpdatePlan();
    }

    /// <summary>Общий переключатель «добавить / создать новую» для файлов без ручного выбора.</summary>
    public void ApplyPreferredMode(bool addToExisting, bool resetPin)
    {
        if (resetPin)
            CoSignPinned = false;
        else if (CoSignPinned)
            return;

        _adjustingSelection = true;
        SelectedCoSignOption = addToExisting
            ? CoSignOptions.FirstOrDefault(option => !option.CreateNew) ?? CoSignOptions.LastOrDefault()
            : CoSignOptions.LastOrDefault(option => option.CreateNew) ?? CoSignOptions.LastOrDefault();
        _adjustingSelection = false;
        UpdatePlan();
    }

    /// <summary>Модель окна сообщает о смене занятости — от неё зависит выбор режима.</summary>
    public void NotifyBusyChanged() => OnPropertyChanged(nameof(CanChooseCoSign));

    /// <summary>
    /// Файлы, которые войдут в объединение: в режиме «добавить» — выбранная подпись
    /// и остальные найденные в папке; в любом режиме — явно приложенные подписи.
    /// </summary>
    public IReadOnlyList<string> PlannedMergeInputs()
    {
        var list = new List<string>();
        if (!SignsStampedCopy && SelectedCoSignOption is { CreateNew: false, SignaturePath: { } selected })
        {
            list.Add(selected);
            foreach (var match in _discovered)
            {
                if (!list.Any(path => SignatureDiscovery.SamePath(path, match.Path)))
                    list.Add(match.Path);
            }
        }

        foreach (var extra in _extraSignatures)
        {
            if (!list.Any(path => SignatureDiscovery.SamePath(path, extra)))
                list.Add(extra);
        }

        return list;
    }

    /// <summary>Куда будет записан результат: выбранный .sig либо «документ.sig».</summary>
    public string PlannedOutputPath =>
        !SignsStampedCopy && SelectedCoSignOption is { CreateNew: false, SignaturePath: { } path }
            ? path
            : FilePath + ".sig";

    /// <summary>
    /// Файл для проверки, извлечения и штампа: выбранный для соподписания,
    /// иначе «документ.sig», иначе первая найденная по содержимому подпись.
    /// </summary>
    public string SignaturePathForTools()
    {
        if (SelectedCoSignOption is { CreateNew: false, SignaturePath: { } selected } && File.Exists(selected))
            return selected;
        var canonical = FilePath + ".sig";
        if (File.Exists(canonical))
            return canonical;
        return _discovered.FirstOrDefault(match => File.Exists(match.Path))?.Path ?? canonical;
    }

    /// <summary>Прикладывает файлы подписей других лиц (дубликаты пропускаются).</summary>
    public int AttachSignatures(IEnumerable<string> sigPaths)
    {
        var added = 0;
        foreach (var path in sigPaths)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                continue;
            if (_extraSignatures.Any(existing => SignatureDiscovery.SamePath(existing, path)))
                continue;
            _extraSignatures.Add(path);
            added++;
        }

        ExtraCount = _extraSignatures.Count;
        // Новая подпись другого лица должна попасть в .sig — файл снова ждёт подписания.
        if (added > 0 && Status == SignStatus.Signed)
            ResetForSigning();
        UpdatePlan();
        return added;
    }

    /// <summary>Возвращает файл в очередь (после смены сертификата или новых подписей).</summary>
    public void ResetForSigning()
    {
        Status = SignStatus.Pending;
        Message = null;
        Warning = null;
        SignaturePath = null;
        SignerCount = 0;
        PreviousSignerCount = 0;
        AppendedToExisting = false;
        UpdatePlan();
    }

    public string StatusDisplay => Status switch
    {
        SignStatus.Pending when IsDiscovering => "поиск подписей документа…",
        SignStatus.Pending => _planText,
        SignStatus.Signing => "Подписывается…",
        SignStatus.Signed when AppendedToExisting && SignerCount == PreviousSignerCount + 1 =>
            $"Подписан: {SignerCount} ({PreviousSignerCount} + ваша) → {FileNameOf(SignaturePath)}{SignedNote}",
        SignStatus.Signed when AppendedToExisting =>
            $"Подписан: {SignerCount} (было {PreviousSignerCount}) → {FileNameOf(SignaturePath)}{SignedNote}",
        SignStatus.Signed when SignerCount <= 1 => $"Подписан: 1, новый файл → {FileNameOf(SignaturePath)}{SignedNote}",
        SignStatus.Signed => $"Подписан: {SignerCount}, новый файл → {FileNameOf(SignaturePath)}{SignedNote}",
        SignStatus.Failed => $"Ошибка: {Message}",
        _ => string.Empty,
    };

    partial void OnSelectedCoSignOptionChanged(CoSignOption? value)
    {
        if (!_adjustingSelection && value is not null)
            CoSignPinned = true;
        UpdatePlan();
        if (!_adjustingSelection && value is not null)
            Owner?.NotifyCoSignSelectionChanged(this);
    }

    private void ApplySharedSelection()
    {
        var add = _sharedWantsAdd && !SignsStampedCopy
            ? CoSignOptions.FirstOrDefault(option => !option.CreateNew)
            : null;
        if (add is null)
        {
            SelectedCoSignOption = CoSignOptions.LastOrDefault(option => option.CreateNew) ?? CoSignOptions.LastOrDefault();
            SharedAddUnavailable = _sharedWantsAdd;
        }
        else
        {
            SelectedCoSignOption = add;
            SharedAddUnavailable = false;
        }
    }

    private void UpdatePlan()
    {
        _planText = BuildPlan();
        OnPropertyChanged(nameof(StatusDisplay));
        OnPropertyChanged(nameof(WarningDisplay));
        OnPropertyChanged(nameof(HasWarning));
    }

    private string BuildPlan()
    {
        // Приложенные файлы, которые и так войдут как найденные в папке, отдельно не называем.
        var planned = !SignsStampedCopy && SelectedCoSignOption is { CreateNew: false }
            ? _discovered.Select(match => match.Path).ToList()
            : new List<string>();
        var outside = _extraSignatures.Count(extra => !planned.Any(path => SignatureDiscovery.SamePath(path, extra)));
        var extras = outside > 0 ? $"; приложенные подписи ({outside}) будут объединены с вашей" : "";
        if (SignsStampedCopy)
            return "будет подписана копия со штампом — для неё создаётся новый файл подписи" + extras;
        if (SelectedCoSignOption is { CreateNew: false, SignaturePath: { } path })
        {
            var others = _discovered.Where(match => !SignatureDiscovery.SamePath(match.Path, path)).ToList();
            var excluded = PlannedDiscovered().SelectMany(match => match.MismatchedSignerNames).Distinct().Count();
            var baseCount = Math.Max(0, (others.Count == 0 ? SelectedCoSignOption.SignerCount : _unionCount) - excluded);
            var sentence =
                $"будет добавлена подпись №{baseCount + 1} к «{Path.GetFileName(path)}» ({SelectedCoSignOption.SignerCount} {SignatureDiscovery.SignerWord(SelectedCoSignOption.SignerCount)})";
            if (others.Count > 0)
                sentence += "; также объединятся: " + string.Join(", ", others.Select(match => "«" + Path.GetFileName(match.Path) + "»"));
            if (_mentionBackup)
                sentence += " (сохранится резервная копия)";
            return sentence + extras;
        }

        var canonical = FilePath + ".sig";
        if (File.Exists(canonical))
            return "будет создан новый файл подписи — существующий «" + Path.GetFileName(canonical)
                + "» будет заменён (сохранится резервная копия)" + extras;

        return "будет создан новый файл подписи" + extras;
    }

    private IEnumerable<SignatureDiscovery.SignatureMatch> PlannedDiscovered() =>
        PlannedMergeInputs()
            .Select(path => _discovered.FirstOrDefault(item => SignatureDiscovery.SamePath(item.Path, path)))
            .OfType<SignatureDiscovery.SignatureMatch>();

    private string? DiscoveryWarning()
    {
        if (Status != SignStatus.Pending || IsDiscovering)
            return null;
        string? fallback = null;
        if (SharedAddUnavailable)
            fallback = SignsStampedCopy
                ? "Для копии со штампом режим «Добавить к существующей» недоступен — будет создан новый файл подписи."
                : "Нет подходящей подписи — будет создан новый файл. Режим «Добавить к существующей», как у первого файла, здесь недоступен.";
        if (SignsStampedCopy)
            return fallback;
        if (fallback is null && _followingShared && !_sharedWantsAdd && _discovered.Count > 0)
            fallback = "Режим «Создать новую», как у первого файла. Найденные подписи не будут объединены: "
                + string.Join(", ", _discovered.Select(match => "«" + Path.GetFileName(match.Path) + "»")) + ".";
        var names = PlannedDiscovered().SelectMany(match => match.MismatchedSignerNames).Distinct().ToList();
        var discovery = names.Count == 0
            ? null
            : "Внимание: при объединении будут исключены подписанты, чья подпись не соответствует документу: "
                + string.Join("; ", names) + ". Перед исключением программа запросит подтверждение.";
        if (fallback is null)
            return discovery;
        return discovery is null ? fallback : fallback + " " + discovery;
    }

    private string SignedNote => string.IsNullOrEmpty(Message) ? string.Empty : $" ⚠ {Message}";

    private static string FileNameOf(string? path) =>
        string.IsNullOrEmpty(path) ? "" : Path.GetFileName(path);

    private static string FormatSize(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} Б",
        < 1024 * 1024 => $"{bytes / 1024.0:0.#} КБ",
        < 1024 * 1024 * 1024 => $"{bytes / (1024.0 * 1024):0.#} МБ",
        _ => $"{bytes / (1024.0 * 1024 * 1024):0.##} ГБ",
    };
}
