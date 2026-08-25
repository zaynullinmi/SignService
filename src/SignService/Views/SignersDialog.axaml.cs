using Avalonia.Controls;

namespace SignService.Views;

/// <summary>Окно «Подписанты и проверка ЭЦП»: текстовый отчёт по подписи.</summary>
public partial class SignersDialog : Window
{
    public SignersDialog()
        : this("")
    {
    }

    public SignersDialog(string reportText)
    {
        InitializeComponent();
        ReportText.Text = reportText;
        CloseButton.Click += (_, _) => Close();
    }
}
