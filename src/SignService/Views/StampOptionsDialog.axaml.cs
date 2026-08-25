using System;
using System.IO;
using System.Linq;
using Avalonia.Controls;
using Avalonia.Platform.Storage;
using SignService.Services;

namespace SignService.Views;

/// <summary>
/// Диалог параметров визуального штампа: страницы (последняя/первая/все/указанные),
/// дата, логотип и режим «подписывать копию со штампом». Показывается перед
/// подписанием со штампом и перед операцией «Штамп на PDF».
/// Возвращает результат либо null при отмене.
/// </summary>
public partial class StampOptionsDialog : Window
{
    /// <summary>Итог диалога: параметры штампа + подписывать ли штампованную копию.</summary>
    public sealed record Result(PdfStamper.StampOptions Options, bool SignCopy);

    private string? _logoPath;

    public StampOptionsDialog()
        : this(new PdfStamper.StampOptions(), signCopy: false, showSignCopy: true)
    {
    }

    public StampOptionsDialog(PdfStamper.StampOptions initial, bool signCopy, bool showSignCopy)
    {
        InitializeComponent();

        (initial.Pages switch
        {
            PdfStamper.StampPages.First => PagesFirst,
            PdfStamper.StampPages.All => PagesAll,
            PdfStamper.StampPages.Custom => PagesCustom,
            _ => PagesLast,
        }).IsChecked = true;
        CustomPagesBox.Text = initial.CustomPages ?? "";
        WithDateBox.IsChecked = initial.WithDate;
        SetLogo(initial.LogoPath);
        SignCopyBox.IsChecked = signCopy;
        SignCopyBox.IsVisible = showSignCopy;

        LogoButton.Click += async (_, _) =>
        {
            var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Логотип организации для штампа",
                AllowMultiple = false,
                FileTypeFilter = new[]
                {
                    new FilePickerFileType("Изображения (*.png, *.jpg)")
                    {
                        Patterns = new[] { "*.png", "*.jpg", "*.jpeg" },
                    },
                },
            });
            if (files.FirstOrDefault()?.TryGetLocalPath() is { } path)
                SetLogo(path);
        };
        ClearLogoButton.Click += (_, _) => SetLogo(null);
        CancelButton.Click += (_, _) => Close(null);
        OkButton.Click += (_, _) =>
        {
            var pages = PagesFirst.IsChecked == true ? PdfStamper.StampPages.First
                : PagesAll.IsChecked == true ? PdfStamper.StampPages.All
                : PagesCustom.IsChecked == true ? PdfStamper.StampPages.Custom
                : PdfStamper.StampPages.Last;

            if (pages == PdfStamper.StampPages.Custom
                && string.IsNullOrWhiteSpace(CustomPagesBox.Text))
            {
                ErrorText.Text = "Укажите страницы, например: 1,3-5.";
                ErrorText.IsVisible = true;
                return;
            }

            Close(new Result(
                new PdfStamper.StampOptions
                {
                    Pages = pages,
                    CustomPages = CustomPagesBox.Text,
                    WithDate = WithDateBox.IsChecked == true,
                    LogoPath = _logoPath,
                },
                SignCopyBox.IsChecked == true));
        };
    }

    private void SetLogo(string? path)
    {
        _logoPath = path is not null && File.Exists(path) ? path : null;
        LogoText.Text = _logoPath is null ? "лого не выбрано" : Path.GetFileName(_logoPath);
    }
}
