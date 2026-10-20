using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Threading;
using Avalonia.VisualTree;
using SignService.Services;
using SignService.ViewModels;
using SignService.Views;

// Смоук интерфейса без экрана (Avalonia.Headless): окна и диалоги загружаются,
// команды меню «Инструменты» и контекстного меню файла привязаны и выполняются.
internal static class UiSmokeTests
{
    public static void Run(string tempRoot)
    {
        // Avalonia и её диспетчер живут в одном потоке — смоук идёт в отдельном.
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try { RunOnUiThread(tempRoot); }
            catch (Exception e) { failure = e; }
        });
        thread.Start();
        thread.Join();
        if (failure is not null)
            throw new Exception("UI smoke failed: " + failure.Message, failure);
    }

    private static void RunOnUiThread(string tempRoot)
    {
        AppBuilder.Configure<SignService.App>()
            .UseSkia()
            .WithInterFont()
            .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false })
            .SetupWithoutStarting();

        var dir = Path.Combine(tempRoot, "ui_smoke");
        Directory.CreateDirectory(dir);
        var document = Path.Combine(dir, "договор.pdf");
        File.WriteAllText(document, "%PDF-1.4");
        var settings = new AppSettings(Path.Combine(dir, "settings")) { CheckUpdatesOnStart = false };
        var vm = new MainWindowViewModel(new CertificateProvider(), new DocumentSigner(), settings,
            new CertificateVault(Path.Combine(dir, "vault")));
        vm.AddFiles(document);

        var window = new MainWindow { DataContext = vm };
        window.Show();
        Dispatcher.UIThread.RunJobs();
        Assert(window.CaptureRenderedFrame() is not null, "main window must render");
        var browse = window.GetVisualDescendants().OfType<Button>().First(b => b.Content?.ToString() == "Обзор…");
        var toolsButton = window.GetVisualDescendants().OfType<Button>().First(b => b.Content?.ToString()?.StartsWith("Инструменты", StringComparison.Ordinal) == true);
        var clear = window.GetVisualDescendants().OfType<Button>().First(b => b.Content?.ToString() == "Очистить список");
        var drop = window.GetVisualDescendants().OfType<Border>().First(b => b.Name == "DropZone");
        var browseAt = browse.TranslatePoint(new Point(0, 0), window)!.Value;
        var toolsAt = toolsButton.TranslatePoint(new Point(0, 0), window)!.Value;
        var clearAt = clear.TranslatePoint(new Point(0, 0), window)!.Value;
        var dropAt = drop.TranslatePoint(new Point(0, 0), window)!.Value;
        Assert(browseAt.Y < dropAt.Y && toolsAt.Y < dropAt.Y && clearAt.Y < dropAt.Y,
            $"browse, tools and clear must sit above the file list (browse {browseAt.Y}, drop {dropAt.Y})");
        Assert(Math.Abs(browseAt.Y - toolsAt.Y) < 4 && Math.Abs(browseAt.Y - clearAt.Y) < 4,
            "browse, tools and clear must share one row");
        Assert(toolsAt.X > browseAt.X && clearAt.X > toolsAt.X, "clear must stay on the right of tools");
        AssertSignButtonOnTheRight(window, dropAt.Y, clear);
        AssertClearLogOnTheSettingsRow(window);
        var labels = window.GetVisualDescendants().OfType<TextBlock>().Select(block => block.Text).ToList();
        Assert(labels.Any(text => text != null && text.StartsWith("Версия ", StringComparison.Ordinal)),
            "main window must show the version");
        Assert(labels.All(text => text == null || !text.Contains("Зайнуллин", StringComparison.Ordinal)),
            "author credit must not stay on the main window");
        Assert(window.GetVisualDescendants().OfType<CheckBox>().Any(box => box.Content?.ToString() == "Применить ко всем"),
            "apply-to-all checkbox must sit on the main window");

        // Контекстное меню — отдельное всплывающее окно вне дерева элементов списка.
        var row = window.GetVisualDescendants().OfType<Border>().First(b => b.ContextMenu is not null);
        var rowButtons = row.GetVisualDescendants().OfType<Button>().ToList();
        Assert(rowButtons.Count >= 2 && rowButtons.All(b => b.Command is not null), "file row buttons must be bound");
        var menu = row.ContextMenu!;
        menu.Open(row);
        Dispatcher.UIThread.RunJobs();
        var items = menu.Items.OfType<MenuItem>().ToList();
        var unbound = items.Where(i => i.Command is null || !i.Command.CanExecute(i.CommandParameter)).Select(i => i.Header).ToList();
        Assert(items.Count >= 9 && unbound.Count == 0, "file context menu commands must be bound: " + string.Join("; ", unbound));
        var inspect = items.First(i => i.Header?.ToString()?.StartsWith("Подписанты", StringComparison.Ordinal) == true);
        inspect.Command!.Execute(inspect.CommandParameter);
        Dispatcher.UIThread.RunJobs();
        Assert(vm.StatusText.Contains("не найден файл подписи"), "context menu command must run for the clicked file: " + vm.StatusText);
        menu.Close();

        var tools = window.GetVisualDescendants().OfType<Button>()
            .First(b => b.Flyout is MenuFlyout && b.Content?.ToString()?.StartsWith("Инструменты", StringComparison.Ordinal) == true);
        var flyout = (MenuFlyout)tools.Flyout!;
        flyout.ShowAt(tools);
        Dispatcher.UIThread.RunJobs();
        var toolItems = flyout.Items.OfType<MenuItem>().ToList();
        Assert(toolItems.Count == 6 && toolItems.All(i => i.Command is not null)
            && toolItems.All(i => i.Header?.ToString()?.StartsWith("Объединить", StringComparison.Ordinal) != true),
            "tools menu must stay bound and no longer offer merge: " + string.Join("; ", toolItems.Select(i => i.Header)));
        flyout.Hide();

        var signers = new[]
        {
            new CmsExtractor.SignerInfo("A", "1. Иванов Иван — сертификат 01"),
            new CmsExtractor.SignerInfo("B", "2. Петров Пётр — сертификат 02"),
        };
        var dialogs = new Window[]
        {
            new SignerDialog(signers),
            new VerificationDialog(settings),
            new StampOptionsDialog(vm.BuildInitialStampOptions(), vm.StampSignCopy, showSignCopy: true),
            new SettingsDialog(vm),
            new AboutDialog(settings),
            new PasswordDialog("Пароль", "Предупреждение", requireConfirmation: true),
            new ConfirmDialog("Подтверждение", "Продолжить?"),
        };
        foreach (var dialog in dialogs)
        {
            dialog.Show();
            Dispatcher.UIThread.RunJobs();
            Assert(dialog.CaptureRenderedFrame() is not null, dialog.GetType().Name + " must render");
            if (dialog is SettingsDialog)
            {
                var backup = dialog.GetVisualDescendants().OfType<CheckBox>()
                    .Any(box => box.Content?.ToString()?.Contains("резервную копию", StringComparison.Ordinal) == true);
                Assert(backup, "settings must offer the .bak checkbox");
            }
            dialog.Close();
        }

        window.Close();
        CheckCoSignRow(tempRoot);
        Console.WriteLine("ui: main window, file context menu (bound, runs for the file), tools menu, 7 dialogs, co-sign row: OK");
    }

    // Строка очереди с найденной подписью: выбор режима, план и предупреждение отображаются;
    // поиск подписей идёт в фоне, его результат применяется в потоке интерфейса.
    private static void CheckCoSignRow(string tempRoot)
    {
        var dir = Path.Combine(tempRoot, "ui_cosign");
        Directory.CreateDirectory(dir);
        var document = Path.Combine(dir, "договор.pdf");
        File.WriteAllBytes(document, "%PDF-1.4 договор"u8.ToArray());
        using var key = RSA.Create(2048);
        using var cert = new CertificateRequest("CN=Подписант А", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddYears(1));
        var signer = new DocumentSigner();
        File.WriteAllBytes(Path.Combine(dir, "договор-.pdf .sig"), signer.Sign(File.ReadAllBytes(document), cert));

        var settings = new AppSettings(Path.Combine(dir, "settings")) { CheckUpdatesOnStart = false };
        var vm = new MainWindowViewModel(new CertificateProvider(), signer, settings, new CertificateVault(Path.Combine(dir, "vault")));
        var window = new MainWindow { DataContext = vm };
        window.Show();
        var adding = vm.AddFilesAsync(document);
        for (var i = 0; !adding.IsCompleted && i < 3000; i++)
        {
            Dispatcher.UIThread.RunJobs();
            Thread.Sleep(10);
        }
        Dispatcher.UIThread.RunJobs();
        Assert(adding.IsCompletedSuccessfully, "signature search must finish");

        var combo = window.GetVisualDescendants().OfType<ComboBox>().Single(box => box.ItemsSource == vm.Files[0].CoSignOptions);
        Assert(combo.ItemCount == 2 && combo.IsEnabled && combo.SelectedItem is CoSignOption { CreateNew: false },
            "co-sign choice must list the found signature and «create new»");
        var texts = window.GetVisualDescendants().OfType<TextBlock>().Select(text => text.Text ?? "").ToList();
        Assert(texts.Any(text => text.Contains("будет добавлена подпись №2")), "plan line must be shown");
        var drop = window.GetVisualDescendants().OfType<Border>().First(b => b.Name == "DropZone");
        var clear = window.GetVisualDescendants().OfType<Button>().First(b => b.Content?.ToString() == "Очистить список");
        AssertSignButtonOnTheRight(window, drop.TranslatePoint(new Point(0, 0), window)!.Value.Y, clear);
        AssertClearLogOnTheSettingsRow(window);
        vm.IsBusy = true;
        Dispatcher.UIThread.RunJobs();
        Assert(!combo.IsEnabled, "co-sign choice must be locked while signing");
        // параметры пакета и очередь не меняются посреди подписания (обход подтверждения)
        var detached = window.GetVisualDescendants().OfType<RadioButton>()
            .First(r => r.Content?.ToString()?.StartsWith("Откреплённая") == true);
        var applyToAll = window.GetVisualDescendants().OfType<CheckBox>().First(c => c.Content?.ToString() == "Применить ко всем");
        Assert(!detached.IsEffectivelyEnabled && !applyToAll.IsEffectivelyEnabled,
            "signing options must be locked while signing");
        Assert(!vm.RemoveFileCommand.CanExecute(vm.Files.First()) && !vm.AddPoaCommand.CanExecute(null),
            "the queue and МЧД must be locked while signing");
        vm.IsBusy = false;
        Dispatcher.UIThread.RunJobs();
        Assert(detached.IsEffectivelyEnabled && vm.RemoveFileCommand.CanExecute(vm.Files.First()) && vm.AddPoaCommand.CanExecute(null),
            "options unlock after signing");
        var frame = window.CaptureRenderedFrame() ?? throw new Exception("co-sign row must render");
        if (Environment.GetEnvironmentVariable("SIGNSERVICE_TEST_OUTPUT") is { Length: > 0 } output)
        {
            Directory.CreateDirectory(output);
            frame.Save(Path.Combine(output, "main-window.png"));
        }

        frame.Dispose();
        window.Close();
    }

    private static void AssertSignButtonOnTheRight(MainWindow window, double dropY, Button clear)
    {
        var sign = window.GetVisualDescendants().OfType<Button>().First(b => b.Content?.ToString() == "Подписать");
        var signAt = sign.TranslatePoint(new Point(0, 0), window)!.Value;
        var signRight = sign.TranslatePoint(new Point(sign.Bounds.Width, 0), window)!.Value.X;
        var clearAt = clear.TranslatePoint(new Point(0, 0), window)!.Value;
        var clearRight = clear.TranslatePoint(new Point(clear.Bounds.Width, 0), window)!.Value.X;
        Assert(signAt.Y > dropY, $"sign button must stay below the file list (sign {signAt.Y}, list {dropY})");
        Assert(Math.Abs(signRight - clearRight) < 2, $"sign button must share the right edge with clear ({signRight} vs {clearRight})");
        Assert(signAt.X > clearAt.X, "sign button must sit on the right side");
    }

    private static void AssertClearLogOnTheSettingsRow(MainWindow window)
    {
        var clearLog = window.GetVisualDescendants().OfType<Button>().First(b => b.Content?.ToString() == "Очистить лог");
        var settings = window.GetVisualDescendants().OfType<Button>().First(b => b.Content?.ToString() == "Настройки…");
        var listClear = window.GetVisualDescendants().OfType<Button>().First(b => b.Content?.ToString() == "Очистить список");
        Assert(clearLog.Command is not null && clearLog.Command.CanExecute(null), "clear-log command must stay bound");
        Assert(window.GetVisualDescendants().OfType<Button>().All(b => b.Content?.ToString() != "Очистить"),
            "the log button must be renamed, not left as «Очистить»");
        var logAt = clearLog.TranslatePoint(new Point(0, 0), window)!.Value;
        var settingsAt = settings.TranslatePoint(new Point(0, 0), window)!.Value;
        var listAt = listClear.TranslatePoint(new Point(0, 0), window)!.Value;
        Assert(Math.Abs(logAt.Y - settingsAt.Y) < 4, $"clear log must share the settings row ({logAt.Y} vs {settingsAt.Y})");
        Assert(logAt.X < settingsAt.X, "clear log must sit on the left of settings");
        Assert(listAt.Y < logAt.Y, "clear list must stay above the log button");
    }

    private static void Assert(bool value, string message)
    {
        if (!value) throw new Exception(message);
    }
}
