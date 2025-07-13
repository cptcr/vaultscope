using System;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using VaultScope.UI.ViewModels;
using VaultScope.UI.Views;

namespace VaultScope.UI
{

public partial class App : Application
{
    public override void Initialize()
    {
        Console.WriteLine("App.Initialize() called");
        try
        {
            AvaloniaXamlLoader.Load(this);
            Console.WriteLine("XAML loaded successfully");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"XAML loading failed: {ex}");
            throw;
        }
    }

    public override void OnFrameworkInitializationCompleted()
    {
        Console.WriteLine("OnFrameworkInitializationCompleted() called");
        try
        {
            if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                Console.WriteLine("Creating MainWindow...");
                // Create main window directly with simplified ViewModel
                var mainWindow = new MainWindow
                {
                    DataContext = new MainWindowViewModel(null, null)
                };

                Console.WriteLine("Setting MainWindow...");
                desktop.MainWindow = mainWindow;
                
                Console.WriteLine("Showing window...");
                // Show the window explicitly
                mainWindow.Show();
                Console.WriteLine("Window shown successfully");
            }
        }
        catch (Exception ex)
        {
            // Create error window if main window fails
            if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                var errorWindow = new Window
                {
                    Title = "VaultScope Enterprise - Error",
                    Width = 600,
                    Height = 400,
                    WindowStartupLocation = WindowStartupLocation.CenterScreen,
                    Content = new TextBlock
                    {
                        Text = $"Failed to initialize application:\n\n{ex}",
                        Margin = new Avalonia.Thickness(20),
                        TextWrapping = Avalonia.Media.TextWrapping.Wrap,
                        Foreground = Avalonia.Media.Brushes.White
                    },
                    Background = Avalonia.Media.Brushes.Black
                };
                desktop.MainWindow = errorWindow;
                errorWindow.Show();
            }
        }

        base.OnFrameworkInitializationCompleted();
    }
}

}