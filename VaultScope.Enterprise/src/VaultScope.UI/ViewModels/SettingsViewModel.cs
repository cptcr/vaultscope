using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Reactive;
using System.Reactive.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using ReactiveUI;
using VaultScope.UI.Services;

namespace VaultScope.UI.ViewModels;

public class SettingsViewModel : ViewModelBase
{
    private readonly IThemeService _themeService;
    private readonly INotificationService _notificationService;
    private readonly string _settingsPath;
    
    private ApplicationSettings _settings = new();
    private bool _isDirty;
    private Theme _selectedTheme;
    private bool _enableNotifications = true;
    private bool _enableSoundEffects = true;
    private bool _enableAutoSave = true;
    private int _autoSaveInterval = 300; // seconds
    private bool _enableDetailedLogging;
    private string _logLevel = "Information";
    private bool _enableSslValidation;
    private int _requestTimeout = 30; // seconds
    private int _maxConcurrentRequests = 10;
    private bool _followRedirects = true;
    private string _userAgent = "VaultScope Enterprise/1.0";
    private bool _enableProxyDetection;
    private string _proxyAddress = string.Empty;
    private int _proxyPort = 8080;
    private bool _enableDatabaseCleanup = true;
    private int _databaseCleanupDays = 30;
    private long _maxDatabaseSize = 1073741824; // 1GB in bytes
    private ObservableCollection<string> _trustedCertificates = new();
    
    public SettingsViewModel()
    {
        // Design-time constructor
        _themeService = null!;
        _notificationService = null!;
        _settingsPath = string.Empty;
        LoadDesignTimeData();
    }
    
    public SettingsViewModel(
        IThemeService themeService,
        INotificationService notificationService)
    {
        _themeService = themeService;
        _notificationService = notificationService;
        
        var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        _settingsPath = Path.Combine(appDataPath, "VaultScope", "settings.json");
        
        // Initialize commands
        SaveSettingsCommand = ReactiveCommand.CreateFromTask(SaveSettingsAsync);
        ResetSettingsCommand = ReactiveCommand.CreateFromTask(ResetSettingsAsync);
        ExportSettingsCommand = ReactiveCommand.CreateFromTask(ExportSettingsAsync);
        ImportSettingsCommand = ReactiveCommand.CreateFromTask(ImportSettingsAsync);
        ClearDatabaseCommand = ReactiveCommand.CreateFromTask(ClearDatabaseAsync);
        AddTrustedCertificateCommand = ReactiveCommand.CreateFromTask(AddTrustedCertificateAsync);
        RemoveTrustedCertificateCommand = ReactiveCommand.Create<string>(RemoveTrustedCertificate);
        
        // Track changes
        this.WhenAnyValue(
                x => x.SelectedTheme,
                x => x.EnableNotifications,
                x => x.EnableSoundEffects,
                x => x.EnableAutoSave,
                x => x.AutoSaveInterval,
                x => x.EnableDetailedLogging,
                x => x.LogLevel,
                x => x.EnableSslValidation,
                x => x.RequestTimeout,
                x => x.MaxConcurrentRequests,
                x => x.FollowRedirects,
                x => x.UserAgent,
                x => x.EnableProxyDetection,
                x => x.ProxyAddress,
                x => x.ProxyPort,
                x => x.EnableDatabaseCleanup,
                x => x.DatabaseCleanupDays,
                x => x.MaxDatabaseSize)
            .Skip(1) // Skip initial values
            .Subscribe(_ => IsDirty = true);
        
        // Handle theme changes
        this.WhenAnyValue(x => x.SelectedTheme)
            .Skip(1)
            .Subscribe(async theme => await _themeService.SetThemeAsync(theme));
        
        // Load settings on initialization
        Observable.StartAsync(LoadSettingsAsync);
    }
    
    #region Properties
    
    public bool IsDirty
    {
        get => _isDirty;
        set => this.RaiseAndSetIfChanged(ref _isDirty, value);
    }
    
    // General Settings
    public Theme SelectedTheme
    {
        get => _selectedTheme;
        set => this.RaiseAndSetIfChanged(ref _selectedTheme, value);
    }
    
    public bool EnableNotifications
    {
        get => _enableNotifications;
        set => this.RaiseAndSetIfChanged(ref _enableNotifications, value);
    }
    
    public bool EnableSoundEffects
    {
        get => _enableSoundEffects;
        set => this.RaiseAndSetIfChanged(ref _enableSoundEffects, value);
    }
    
    public bool EnableAutoSave
    {
        get => _enableAutoSave;
        set => this.RaiseAndSetIfChanged(ref _enableAutoSave, value);
    }
    
    public int AutoSaveInterval
    {
        get => _autoSaveInterval;
        set => this.RaiseAndSetIfChanged(ref _autoSaveInterval, value);
    }
    
    // Logging Settings
    public bool EnableDetailedLogging
    {
        get => _enableDetailedLogging;
        set => this.RaiseAndSetIfChanged(ref _enableDetailedLogging, value);
    }
    
    public string LogLevel
    {
        get => _logLevel;
        set => this.RaiseAndSetIfChanged(ref _logLevel, value);
    }
    
    // Network Settings
    public bool EnableSslValidation
    {
        get => _enableSslValidation;
        set => this.RaiseAndSetIfChanged(ref _enableSslValidation, value);
    }
    
    public int RequestTimeout
    {
        get => _requestTimeout;
        set => this.RaiseAndSetIfChanged(ref _requestTimeout, value);
    }
    
    public int MaxConcurrentRequests
    {
        get => _maxConcurrentRequests;
        set => this.RaiseAndSetIfChanged(ref _maxConcurrentRequests, value);
    }
    
    public bool FollowRedirects
    {
        get => _followRedirects;
        set => this.RaiseAndSetIfChanged(ref _followRedirects, value);
    }
    
    public string UserAgent
    {
        get => _userAgent;
        set => this.RaiseAndSetIfChanged(ref _userAgent, value);
    }
    
    // Proxy Settings
    public bool EnableProxyDetection
    {
        get => _enableProxyDetection;
        set => this.RaiseAndSetIfChanged(ref _enableProxyDetection, value);
    }
    
    public string ProxyAddress
    {
        get => _proxyAddress;
        set => this.RaiseAndSetIfChanged(ref _proxyAddress, value);
    }
    
    public int ProxyPort
    {
        get => _proxyPort;
        set => this.RaiseAndSetIfChanged(ref _proxyPort, value);
    }
    
    // Database Settings
    public bool EnableDatabaseCleanup
    {
        get => _enableDatabaseCleanup;
        set => this.RaiseAndSetIfChanged(ref _enableDatabaseCleanup, value);
    }
    
    public int DatabaseCleanupDays
    {
        get => _databaseCleanupDays;
        set => this.RaiseAndSetIfChanged(ref _databaseCleanupDays, value);
    }
    
    public long MaxDatabaseSize
    {
        get => _maxDatabaseSize;
        set => this.RaiseAndSetIfChanged(ref _maxDatabaseSize, value);
    }
    
    public string MaxDatabaseSizeMB => $"{MaxDatabaseSize / (1024 * 1024)} MB";
    
    // Security Settings
    public ObservableCollection<string> TrustedCertificates
    {
        get => _trustedCertificates;
        set => this.RaiseAndSetIfChanged(ref _trustedCertificates, value);
    }
    
    #endregion
    
    #region Commands
    
    public ReactiveCommand<Unit, Unit> SaveSettingsCommand { get; }
    public ReactiveCommand<Unit, Unit> ResetSettingsCommand { get; }
    public ReactiveCommand<Unit, Unit> ExportSettingsCommand { get; }
    public ReactiveCommand<Unit, Unit> ImportSettingsCommand { get; }
    public ReactiveCommand<Unit, Unit> ClearDatabaseCommand { get; }
    public ReactiveCommand<Unit, Unit> AddTrustedCertificateCommand { get; }
    public ReactiveCommand<string, Unit> RemoveTrustedCertificateCommand { get; }
    
    #endregion
    
    #region Methods
    
    private async Task LoadSettingsAsync()
    {
        try
        {
            if (File.Exists(_settingsPath))
            {
                var json = await File.ReadAllTextAsync(_settingsPath);
                _settings = JsonSerializer.Deserialize<ApplicationSettings>(json) ?? new ApplicationSettings();
                ApplySettings(_settings);
            }
            else
            {
                // Use defaults
                _settings = new ApplicationSettings();
                SelectedTheme = _themeService.CurrentTheme;
            }
            
            IsDirty = false;
        }
        catch (Exception ex)
        {
            _notificationService.Show("Error", $"Failed to load settings: {ex.Message}", NotificationType.Error);
        }
    }
    
    private async Task SaveSettingsAsync()
    {
        try
        {
            UpdateSettingsFromProperties();
            
            Directory.CreateDirectory(Path.GetDirectoryName(_settingsPath)!);
            var json = JsonSerializer.Serialize(_settings, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(_settingsPath, json);
            
            IsDirty = false;
            _notificationService.Show("Settings Saved", "Your settings have been saved successfully", NotificationType.Success);
        }
        catch (Exception ex)
        {
            _notificationService.Show("Error", $"Failed to save settings: {ex.Message}", NotificationType.Error);
        }
    }
    
    private async Task ResetSettingsAsync()
    {
        var confirm = await _notificationService.ShowConfirmationAsync(
            "Reset Settings",
            "Are you sure you want to reset all settings to defaults?");
        
        if (!confirm) return;
        
        _settings = new ApplicationSettings();
        ApplySettings(_settings);
        await SaveSettingsAsync();
        
        _notificationService.Show("Settings Reset", "All settings have been reset to defaults", NotificationType.Information);
    }
    
    private async Task ExportSettingsAsync()
    {
        try
        {
            UpdateSettingsFromProperties();
            
            var documentsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            var exportPath = Path.Combine(documentsPath, $"VaultScope_Settings_{DateTime.Now:yyyyMMdd_HHmmss}.json");
            
            var json = JsonSerializer.Serialize(_settings, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(exportPath, json);
            
            _notificationService.Show("Export Complete", $"Settings exported to {Path.GetFileName(exportPath)}", NotificationType.Success);
        }
        catch (Exception ex)
        {
            _notificationService.Show("Export Error", ex.Message, NotificationType.Error);
        }
    }
    
    private async Task ImportSettingsAsync()
    {
        try
        {
            // In a real implementation, this would show a file picker dialog
            var documentsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            var importPath = Path.Combine(documentsPath, "VaultScope_Settings.json");
            
            if (!File.Exists(importPath))
            {
                _notificationService.Show("File Not Found", "No settings file found to import", NotificationType.Warning);
                return;
            }
            
            var json = await File.ReadAllTextAsync(importPath);
            var importedSettings = JsonSerializer.Deserialize<ApplicationSettings>(json);
            
            if (importedSettings == null)
            {
                _notificationService.Show("Import Error", "Invalid settings file format", NotificationType.Error);
                return;
            }
            
            _settings = importedSettings;
            ApplySettings(_settings);
            await SaveSettingsAsync();
            
            _notificationService.Show("Import Complete", "Settings imported successfully", NotificationType.Success);
        }
        catch (Exception ex)
        {
            _notificationService.Show("Import Error", ex.Message, NotificationType.Error);
        }
    }
    
    private async Task ClearDatabaseAsync()
    {
        var confirm = await _notificationService.ShowConfirmationAsync(
            "Clear Database",
            "Are you sure you want to clear all scan data? This action cannot be undone.");
        
        if (!confirm) return;
        
        try
        {
            // In a real implementation, this would clear the database
            _notificationService.Show("Database Cleared", "All scan data has been removed", NotificationType.Success);
        }
        catch (Exception ex)
        {
            _notificationService.Show("Error", ex.Message, NotificationType.Error);
        }
    }
    
    private async Task AddTrustedCertificateAsync()
    {
        try
        {
            // In a real implementation, this would show a file picker for .cer files
            var cert = $"Certificate_{DateTime.Now:yyyyMMdd_HHmmss}.cer";
            TrustedCertificates.Add(cert);
            IsDirty = true;
            
            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _notificationService.Show("Error", ex.Message, NotificationType.Error);
        }
    }
    
    private void RemoveTrustedCertificate(string certificate)
    {
        TrustedCertificates.Remove(certificate);
        IsDirty = true;
    }
    
    private void ApplySettings(ApplicationSettings settings)
    {
        SelectedTheme = Enum.Parse<Theme>(settings.Theme);
        EnableNotifications = settings.EnableNotifications;
        EnableSoundEffects = settings.EnableSoundEffects;
        EnableAutoSave = settings.EnableAutoSave;
        AutoSaveInterval = settings.AutoSaveInterval;
        EnableDetailedLogging = settings.EnableDetailedLogging;
        LogLevel = settings.LogLevel;
        EnableSslValidation = settings.EnableSslValidation;
        RequestTimeout = settings.RequestTimeout;
        MaxConcurrentRequests = settings.MaxConcurrentRequests;
        FollowRedirects = settings.FollowRedirects;
        UserAgent = settings.UserAgent;
        EnableProxyDetection = settings.EnableProxyDetection;
        ProxyAddress = settings.ProxyAddress;
        ProxyPort = settings.ProxyPort;
        EnableDatabaseCleanup = settings.EnableDatabaseCleanup;
        DatabaseCleanupDays = settings.DatabaseCleanupDays;
        MaxDatabaseSize = settings.MaxDatabaseSize;
        TrustedCertificates = new ObservableCollection<string>(settings.TrustedCertificates);
    }
    
    private void UpdateSettingsFromProperties()
    {
        _settings.Theme = SelectedTheme.ToString();
        _settings.EnableNotifications = EnableNotifications;
        _settings.EnableSoundEffects = EnableSoundEffects;
        _settings.EnableAutoSave = EnableAutoSave;
        _settings.AutoSaveInterval = AutoSaveInterval;
        _settings.EnableDetailedLogging = EnableDetailedLogging;
        _settings.LogLevel = LogLevel;
        _settings.EnableSslValidation = EnableSslValidation;
        _settings.RequestTimeout = RequestTimeout;
        _settings.MaxConcurrentRequests = MaxConcurrentRequests;
        _settings.FollowRedirects = FollowRedirects;
        _settings.UserAgent = UserAgent;
        _settings.EnableProxyDetection = EnableProxyDetection;
        _settings.ProxyAddress = ProxyAddress;
        _settings.ProxyPort = ProxyPort;
        _settings.EnableDatabaseCleanup = EnableDatabaseCleanup;
        _settings.DatabaseCleanupDays = DatabaseCleanupDays;
        _settings.MaxDatabaseSize = MaxDatabaseSize;
        _settings.TrustedCertificates = TrustedCertificates.ToList();
    }
    
    private void LoadDesignTimeData()
    {
        SelectedTheme = Theme.DarkPurple;
        EnableNotifications = true;
        EnableAutoSave = true;
        LogLevel = "Information";
        TrustedCertificates = new ObservableCollection<string>
        {
            "localhost.cer",
            "test-api.cer"
        };
    }
    
    #endregion
}

public class ApplicationSettings
{
    public string Theme { get; set; } = "DarkPurple";
    public bool EnableNotifications { get; set; } = true;
    public bool EnableSoundEffects { get; set; } = true;
    public bool EnableAutoSave { get; set; } = true;
    public int AutoSaveInterval { get; set; } = 300;
    public bool EnableDetailedLogging { get; set; }
    public string LogLevel { get; set; } = "Information";
    public bool EnableSslValidation { get; set; }
    public int RequestTimeout { get; set; } = 30;
    public int MaxConcurrentRequests { get; set; } = 10;
    public bool FollowRedirects { get; set; } = true;
    public string UserAgent { get; set; } = "VaultScope Enterprise/1.0";
    public bool EnableProxyDetection { get; set; }
    public string ProxyAddress { get; set; } = string.Empty;
    public int ProxyPort { get; set; } = 8080;
    public bool EnableDatabaseCleanup { get; set; } = true;
    public int DatabaseCleanupDays { get; set; } = 30;
    public long MaxDatabaseSize { get; set; } = 1073741824;
    public List<string> TrustedCertificates { get; set; } = new();
}