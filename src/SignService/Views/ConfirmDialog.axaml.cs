using Avalonia.Controls;

namespace SignService.Views;

/// <summary>Простой диалог «Да/Нет». Возвращает true при подтверждении.</summary>
public partial class ConfirmDialog : Window
{
    public ConfirmDialog()
        : this("Подтверждение", "Продолжить?")
    {
    }

    public ConfirmDialog(string title, string message)
    {
        InitializeComponent();
        Title = title;
        MessageText.Text = message;
        YesButton.Click += (_, _) => Close(true);
        NoButton.Click += (_, _) => Close(false);
    }
}
