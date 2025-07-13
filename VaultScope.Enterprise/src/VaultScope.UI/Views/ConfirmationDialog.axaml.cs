using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;

namespace VaultScope.UI.Views;

public partial class ConfirmationDialog : Window
{
    public static readonly StyledProperty<string> MessageProperty =
        AvaloniaProperty.Register<ConfirmationDialog, string>(nameof(Message), string.Empty);
    
    public string Message
    {
        get => GetValue(MessageProperty);
        set => SetValue(MessageProperty, value);
    }
    
    public ConfirmationDialog()
    {
        InitializeComponent();
        DataContext = this;
    }
    
    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
    
    private void OkButton_Click(object? sender, RoutedEventArgs e)
    {
        Close(true);
    }
    
    private void CancelButton_Click(object? sender, RoutedEventArgs e)
    {
        Close(false);
    }
}