using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using SignService.Services;
using SignService.ViewModels;
using SignService.Views;

namespace SignService;

public class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var viewModel = new MainWindowViewModel(new CertificateProvider(), new DocumentSigner());

            // Пути к файлам, переданные аргументами командной строки
            // (например, через «Открыть с помощью»), сразу попадают в очередь.
            if (desktop.Args is { Length: > 0 } args)
                viewModel.AddFiles(args);

            desktop.MainWindow = new MainWindow
            {
                DataContext = viewModel,
            };
        }

        base.OnFrameworkInitializationCompleted();
    }
}
