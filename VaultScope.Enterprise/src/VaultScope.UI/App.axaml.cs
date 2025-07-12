using System;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using VaultScope.UI.Services;
using VaultScope.UI.ViewModels;
using VaultScope.UI.Views;

namespace VaultScope.UI;

public partial class App : Application
{
    public static IServiceProvider ServiceProvider { get; set; } = null!;
    
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override async void OnFrameworkInitializationCompleted()
    {
        // Show splash screen
        var splash = new SplashScreen();
        
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            // Set splash as initial window
            desktop.MainWindow = splash;
            splash.Show();
            
            try
            {
                // Initialize application
                await InitializeApplicationAsync(splash);
                
                // Create main window
                var mainViewModel = ServiceProvider.GetRequiredService<MainWindowViewModel>();
                var mainWindow = new MainWindow
                {
                    DataContext = mainViewModel
                };
                
                // Set window properties
                mainWindow.Width = 1400;
                mainWindow.Height = 900;
                mainWindow.WindowStartupLocation = WindowStartupLocation.CenterScreen;
                
                // Replace splash with main window
                desktop.MainWindow = mainWindow;
                mainWindow.Show();
                splash.Close();
                
                // Handle shutdown
                desktop.ShutdownRequested += OnShutdownRequested;
            }
            catch (Exception ex)
            {
                // Show error in splash
                await splash.ShowErrorAsync($"Failed to initialize application: {ex.Message}");
                desktop.Shutdown();
            }
        }

        base.OnFrameworkInitializationCompleted();
    }
    
    private async Task InitializeApplicationAsync(SplashScreen splash)
    {
        // Update splash progress
        await splash.UpdateProgressAsync(0.2, "Initializing services...");
        await Task.Delay(200); // Allow UI to update
        
        // Initialize theme
        await splash.UpdateProgressAsync(0.4, "Loading theme...");
        var themeService = ServiceProvider.GetRequiredService<IThemeService>();
        await themeService.InitializeAsync();
        
        // Check for updates (in production)
        await splash.UpdateProgressAsync(0.6, "Checking for updates...");
        await CheckForUpdatesAsync();
        
        // Load user settings
        await splash.UpdateProgressAsync(0.8, "Loading settings...");
        await LoadUserSettingsAsync();
        
        // Final initialization
        await splash.UpdateProgressAsync(1.0, "Starting VaultScope...");
        await Task.Delay(500); // Show complete state briefly
    }
    
    private async Task CheckForUpdatesAsync()
    {
        // In production, check for updates
        await Task.Delay(500); // Simulate update check
    }
    
    private async Task LoadUserSettingsAsync()
    {
        // Load user preferences
        await Task.Delay(300); // Simulate settings load
    }
    
    private void OnShutdownRequested(object? sender, ShutdownRequestedEventArgs e)
    {
        // Cleanup
        if (Resources.TryGetValue("Host", out var hostObj) && hostObj is IHost host)
        {
            host.Dispose();
        }
    }
    
    public static void ShowNotification(string title, string message, NotificationType type = NotificationType.Information)
    {
        Dispatcher.UIThread.Post(() =>
        {
            var notificationService = ServiceProvider.GetRequiredService<INotificationService>();
            notificationService.Show(title, message, type);
        });
    }
    
    public static async Task<bool> ShowConfirmationAsync(string title, string message)
    {
        var tcs = new TaskCompletionSource<bool>();
        
        Dispatcher.UIThread.Post(async () =>
        {
            if (Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop && 
                desktop.MainWindow != null)
            {
                var dialog = new ConfirmationDialog
                {
                    Title = title,
                    Message = message
                };
                
                var result = await dialog.ShowDialog<bool>(desktop.MainWindow);
                tcs.SetResult(result);
            }
            else
            {
                tcs.SetResult(false);
            }
        });
        
        return await tcs.Task;
    }
}