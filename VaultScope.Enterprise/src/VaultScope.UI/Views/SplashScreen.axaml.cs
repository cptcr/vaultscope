using System;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;

namespace VaultScope.UI.Views;

public partial class SplashScreen : Window
{
    public SplashScreen()
    {
        InitializeComponent();
    }
    
    public async Task UpdateProgressAsync(double value, string status)
    {
        await Dispatcher.UIThread.InvokeAsync(() =>
        {
            LoadingProgress.Value = value;
            StatusText.Text = status;
        });
    }
    
    public async Task ShowErrorAsync(string error)
    {
        await Dispatcher.UIThread.InvokeAsync(() =>
        {
            ErrorText.Text = error;
            ErrorContainer.IsVisible = true;
        });
    }
    
    private void OnExitClick(object? sender, RoutedEventArgs e)
    {
        Close();
    }
}