using Avalonia.Controls;
using Avalonia.Interactivity;

namespace SignService.Views;

/// <summary>
/// Диалог ввода пароля: для сохранения сертификата на ПК (с предупреждением
/// и повторным вводом) и для разблокировки сохранённого сертификата.
/// Возвращает пароль либо null при отмене.
/// </summary>
public partial class PasswordDialog : Window
{
    private readonly bool _requireConfirmation;

    public PasswordDialog()
        : this("Введите пароль.", null, requireConfirmation: false)
    {
    }

    public PasswordDialog(string message, string? warning, bool requireConfirmation)
    {
        InitializeComponent();
        _requireConfirmation = requireConfirmation;

        MessageText.Text = message;
        if (!string.IsNullOrEmpty(warning))
        {
            WarningText.Text = warning;
            WarningText.IsVisible = true;
        }

        ConfirmPanel.IsVisible = requireConfirmation;

        OkButton.Click += OnOk;
        CancelButton.Click += (_, _) => Close(null);
        Opened += (_, _) => PasswordBox.Focus();
    }

    private void OnOk(object? sender, RoutedEventArgs e)
    {
        var password = PasswordBox.Text ?? "";
        if (password.Length == 0)
        {
            ShowError("Пароль не может быть пустым.");
            return;
        }

        if (_requireConfirmation && password != (ConfirmBox.Text ?? ""))
        {
            ShowError("Пароли не совпадают.");
            return;
        }

        Close(password);
    }

    private void ShowError(string text)
    {
        ErrorText.Text = text;
        ErrorText.IsVisible = true;
    }
}
