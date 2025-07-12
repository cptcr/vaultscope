using System;
using Avalonia;
using Avalonia.ReactiveUI;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using VaultScope.Infrastructure;

namespace VaultScope.UI;

internal class Program
{
    // Initialization code. Don't use any Avalonia, third-party APIs or any
    // SynchronizationContext-reliant code before AppMain is called: things aren't initialized
    // yet and stuff might break.
    [STAThread]
    public static void Main(string[] args)
    {
        try
        {
            BuildAvaloniaApp()
                .StartWithClassicDesktopLifetime(args);
        }
        catch (Exception ex)
        {
            // Log to file since we might not have UI
            var logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), 
                "VaultScope", "crash.log");
            Directory.CreateDirectory(Path.GetDirectoryName(logPath)!);
            File.WriteAllText(logPath, $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}] FATAL: {ex}");
            throw;
        }
    }

    // Avalonia configuration, don't remove; also used by visual designer.
    public static AppBuilder BuildAvaloniaApp()
    {
        return AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace()
            .UseReactiveUI()
            .AfterSetup(async builder =>
            {
                // Initialize services after Avalonia is set up
                var host = CreateHostBuilder().Build();
                
                // Store host in app resources for disposal
                if (Application.Current != null)
                {
                    Application.Current.Resources["Host"] = host;
                }
                
                // Initialize database
                await host.Services.InitializeDatabaseAsync();
                
                // Set global service provider
                App.ServiceProvider = host.Services;
            });
    }
    
    private static IHostBuilder CreateHostBuilder()
    {
        return Host.CreateDefaultBuilder()
            .ConfigureServices((context, services) =>
            {
                // Add infrastructure services
                services.AddInfrastructure(context.Configuration);
                
                // Add UI services
                services.AddSingleton<App>();
                
                // Add ViewModels
                services.AddTransient<ViewModels.MainWindowViewModel>();
                services.AddTransient<ViewModels.DashboardViewModel>();
                services.AddTransient<ViewModels.ScannerViewModel>();
                services.AddTransient<ViewModels.ReportsViewModel>();
                services.AddTransient<ViewModels.SettingsViewModel>();
                services.AddTransient<ViewModels.ScanResultDetailViewModel>();
                
                // Add navigation service
                services.AddSingleton<Services.INavigationService, Services.NavigationService>();
                services.AddSingleton<Services.INotificationService, Services.NotificationService>();
                services.AddSingleton<Services.IThemeService, Services.ThemeService>();
                
                // Configure logging
                services.AddLogging(builder =>
                {
                    builder.SetMinimumLevel(LogLevel.Information);
                    builder.AddConsole();
                    builder.AddDebug();
                    
                    // Add file logging
                    var logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), 
                        "VaultScope", "logs");
                    Directory.CreateDirectory(logPath);
                    builder.AddFile(Path.Combine(logPath, "vaultscope-{Date}.log"));
                });
            })
            .UseConsoleLifetime();
    }
}