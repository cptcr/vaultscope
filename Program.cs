using System;
using System.Diagnostics;
using System.IO;

namespace VaultScope;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Starting VaultScope Enterprise...");
        
        var enterprisePath = Path.Combine(Directory.GetCurrentDirectory(), "VaultScope.Enterprise");
        var uiProjectPath = Path.Combine(enterprisePath, "src", "VaultScope.UI", "VaultScope.UI.csproj");
        
        if (!File.Exists(uiProjectPath))
        {
            Console.WriteLine($"Error: Could not find UI project at {uiProjectPath}");
            return;
        }
        
        var startInfo = new ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = $"run --project \"{uiProjectPath}\"",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = enterprisePath
        };
        
        try
        {
            using var process = Process.Start(startInfo);
            if (process != null)
            {
                process.OutputDataReceived += (sender, e) => Console.WriteLine(e.Data);
                process.ErrorDataReceived += (sender, e) => Console.Error.WriteLine(e.Data);
                
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                
                process.WaitForExit();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error starting VaultScope: {ex.Message}");
        }
    }
}
