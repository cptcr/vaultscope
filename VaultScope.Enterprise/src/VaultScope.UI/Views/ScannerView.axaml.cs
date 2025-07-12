using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace VaultScope.UI.Views;

public partial class ScannerView : UserControl
{
    public ScannerView()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}