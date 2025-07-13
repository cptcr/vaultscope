using System;
using System.IO;
using Avalonia;
using Avalonia.ReactiveUI;

namespace VaultScope.UI;

internal class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        Console.WriteLine("VaultScope Enterprise starting...");
        try
        {
            Console.WriteLine("Building Avalonia app...");
            var app = BuildAvaloniaApp();
            Console.WriteLine("Starting with classic desktop lifetime...");
            app.StartWithClassicDesktopLifetime(args);
            Console.WriteLine("Application started successfully.");
        }
        catch (Exception ex)
        {
            // Create logs directory
            var logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VaultScope");
            Directory.CreateDirectory(logDir);
            
            // Log the crash
            var crashPath = Path.Combine(logDir, "crash.log");
            File.WriteAllText(crashPath, $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}] FATAL: {ex}");
            
            // Also write to console
            Console.WriteLine($"FATAL ERROR: {ex}");
            Console.WriteLine($"Log written to: {crashPath}");
            
            // Only wait for input if we're in an interactive console
            if (Environment.UserInteractive && !Console.IsInputRedirected)
            {
                Console.WriteLine("Press any key to exit...");
                try
                {
                    Console.ReadKey();
                }
                catch
                {
                    // Ignore if can't read key
                }
            }
            throw;
        }
    }

    public static AppBuilder BuildAvaloniaApp()
    {
        Console.WriteLine("Configuring AppBuilder...");
        return AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace()
            .UseReactiveUI();
    }
}