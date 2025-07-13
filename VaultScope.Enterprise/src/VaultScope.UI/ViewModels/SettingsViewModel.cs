using System;
using System.Collections.ObjectModel;
using System.Reactive;
using ReactiveUI;

namespace VaultScope.UI.ViewModels;

public class SettingsViewModel : ViewModelBase
{
    private string _apiTimeout = "30000";
    private bool _enableLogging = true;
    private string _logLevel = "Information";
    
    public string ApiTimeout
    {
        get => _apiTimeout;
        set => this.RaiseAndSetIfChanged(ref _apiTimeout, value);
    }
    
    public bool EnableLogging
    {
        get => _enableLogging;
        set => this.RaiseAndSetIfChanged(ref _enableLogging, value);
    }
    
    public string LogLevel
    {
        get => _logLevel;
        set => this.RaiseAndSetIfChanged(ref _logLevel, value);
    }
    
    public ObservableCollection<string> LogLevels { get; } = new()
    {
        "Debug", "Information", "Warning", "Error", "Critical"
    };
    
    public ObservableCollection<string> TrustedCertificates { get; } = new();
    
    // Commands
    public ReactiveCommand<Unit, Unit> SaveSettingsCommand { get; }
    public ReactiveCommand<Unit, Unit> ResetSettingsCommand { get; }
    public ReactiveCommand<Unit, Unit> ExportSettingsCommand { get; }
    public ReactiveCommand<Unit, Unit> ImportSettingsCommand { get; }
    public ReactiveCommand<Unit, Unit> ClearDatabaseCommand { get; }
    public ReactiveCommand<Unit, Unit> AddTrustedCertificateCommand { get; }
    public ReactiveCommand<string, Unit> RemoveTrustedCertificateCommand { get; }
    
    public SettingsViewModel()
    {
        SaveSettingsCommand = ReactiveCommand.Create(SaveSettings);
        ResetSettingsCommand = ReactiveCommand.Create(ResetSettings);
        ExportSettingsCommand = ReactiveCommand.Create(ExportSettings);
        ImportSettingsCommand = ReactiveCommand.Create(ImportSettings);
        ClearDatabaseCommand = ReactiveCommand.Create(ClearDatabase);
        AddTrustedCertificateCommand = ReactiveCommand.Create(AddTrustedCertificate);
        RemoveTrustedCertificateCommand = ReactiveCommand.Create<string>(RemoveTrustedCertificate);
        
        LoadSettings();
    }
    
    private void SaveSettings()
    {
        // Save settings to configuration
    }
    
    private void ResetSettings()
    {
        ApiTimeout = "30000";
        EnableLogging = true;
        LogLevel = "Information";
    }
    
    private void ExportSettings()
    {
        // Export settings to file
    }
    
    private void ImportSettings()
    {
        // Import settings from file
    }
    
    private void ClearDatabase()
    {
        // Clear all data from database
    }
    
    private void AddTrustedCertificate()
    {
        // Add a trusted certificate
    }
    
    private void RemoveTrustedCertificate(string certificate)
    {
        TrustedCertificates.Remove(certificate);
    }
    
    private void LoadSettings()
    {
        // Load settings from configuration
    }
}