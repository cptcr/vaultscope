using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Markup.Xaml.Styling;
using Avalonia.Styling;

namespace VaultScope.UI.Services;

public class ThemeService : IThemeService
{
    private readonly string _settingsPath;
    private Theme _currentTheme = Theme.DarkPurple;
    
    public Theme CurrentTheme => _currentTheme;
    
    public ThemeService()
    {
        var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        _settingsPath = Path.Combine(appDataPath, "VaultScope", "theme.json");
    }
    
    public async Task InitializeAsync()
    {
        await LoadThemeSettingsAsync();
        ApplyTheme(_currentTheme);
    }
    
    public async Task SetThemeAsync(Theme theme)
    {
        _currentTheme = theme;
        ApplyTheme(theme);
        await SaveThemeSettingsAsync();
    }
    
    private void ApplyTheme(Theme theme)
    {
        if (Application.Current == null) return;
        
        var themeUri = theme switch
        {
            Theme.DarkPurple => new Uri("avares://VaultScope.UI/Themes/DarkPurpleTheme.axaml"),
            Theme.DarkBlue => new Uri("avares://VaultScope.UI/Themes/DarkBlueTheme.axaml"),
            Theme.Light => new Uri("avares://VaultScope.UI/Themes/LightTheme.axaml"),
            _ => new Uri("avares://VaultScope.UI/Themes/DarkPurpleTheme.axaml")
        };
        
        // In a real implementation, we would dynamically load theme resources
        // For now, the DarkPurple theme is loaded by default
    }
    
    private async Task LoadThemeSettingsAsync()
    {
        try
        {
            if (File.Exists(_settingsPath))
            {
                var json = await File.ReadAllTextAsync(_settingsPath);
                var settings = JsonSerializer.Deserialize<ThemeSettings>(json);
                if (settings != null && Enum.TryParse<Theme>(settings.ThemeName, out var theme))
                {
                    _currentTheme = theme;
                }
            }
        }
        catch
        {
            // Use default theme
        }
    }
    
    private async Task SaveThemeSettingsAsync()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_settingsPath)!);
            var settings = new ThemeSettings { ThemeName = _currentTheme.ToString() };
            var json = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(_settingsPath, json);
        }
        catch
        {
            // Log error
        }
    }
    
    private class ThemeSettings
    {
        public string ThemeName { get; set; } = "DarkPurple";
    }
}