using Avalonia.Controls;
using SignService.ViewModels;

namespace SignService.Views;

/// <summary>Окно настроек: резервная копия .sig, штамп времени (CAdES-T) и адрес TSA.</summary>
public partial class SettingsDialog : Window
{
    public SettingsDialog()
    {
        InitializeComponent();
        CloseButton.Click += (_, _) => Close();
    }

    public SettingsDialog(MainWindowViewModel viewModel)
        : this()
    {
        DataContext = viewModel; // настройки сохраняются самим VM при изменении
    }
}
