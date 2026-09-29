using System.Collections.Generic;
using System.Linq;
using Avalonia.Controls;
using SignService.Services;

namespace SignService.Views;

public partial class SignerDialog : Window
{
    public SignerDialog() : this(System.Array.Empty<CmsExtractor.SignerInfo>()) { }

    public SignerDialog(IReadOnlyList<CmsExtractor.SignerInfo> signers)
    {
        InitializeComponent();
        SignersList.ItemsSource = signers.Select(s => s.DisplayName).ToList();
        SignersList.SelectionChanged += (_, _) => RemoveButton.IsEnabled = SignersList.SelectedIndex >= 0;
        CancelButton.Click += (_, _) => Close((string?)null);
        RemoveButton.Click += (_, _) =>
        {
            if (SignersList.SelectedIndex >= 0)
                Close(signers[SignersList.SelectedIndex].Id);
        };
    }
}
