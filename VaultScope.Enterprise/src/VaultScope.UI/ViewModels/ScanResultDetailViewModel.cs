using System;
using System.Collections.ObjectModel;
using System.Reactive;
using System.Threading.Tasks;
using ReactiveUI;
using VaultScope.Core.Models;
using VaultScope.Infrastructure.Data.Repositories;
using VaultScope.UI.Services;

namespace VaultScope.UI.ViewModels;

public class ScanResultDetailViewModel : ViewModelBase, INavigationAware
{
    private readonly IScanResultRepository? _scanResultRepository;
    private ScanResult? _scanResult;
    private bool _isLoading;
    private Vulnerability? _selectedVulnerability;
    private string _statusMessage = "Ready";
    
    public ScanResult? ScanResult
    {
        get => _scanResult;
        set => this.RaiseAndSetIfChanged(ref _scanResult, value);
    }
    
    public bool IsLoading
    {
        get => _isLoading;
        set => this.RaiseAndSetIfChanged(ref _isLoading, value);
    }
    
    public Vulnerability? SelectedVulnerability
    {
        get => _selectedVulnerability;
        set => this.RaiseAndSetIfChanged(ref _selectedVulnerability, value);
    }
    
    public string StatusMessage
    {
        get => _statusMessage;
        set => this.RaiseAndSetIfChanged(ref _statusMessage, value);
    }
    
    public ObservableCollection<Vulnerability> Vulnerabilities { get; } = new();
    
    // Commands
    public ReactiveCommand<Unit, Unit> RefreshCommand { get; }
    public ReactiveCommand<Unit, Unit> ExportReportCommand { get; }
    public ReactiveCommand<Unit, Unit> ShareReportCommand { get; }
    public ReactiveCommand<Vulnerability, Unit> ViewVulnerabilityDetailsCommand { get; }
    public ReactiveCommand<Unit, Unit> BackCommand { get; }
    
    public ScanResultDetailViewModel(IScanResultRepository? scanResultRepository = null)
    {
        _scanResultRepository = scanResultRepository;
        
        RefreshCommand = ReactiveCommand.Create(Refresh);
        ExportReportCommand = ReactiveCommand.Create(ExportReport);
        ShareReportCommand = ReactiveCommand.Create(ShareReport);
        ViewVulnerabilityDetailsCommand = ReactiveCommand.Create<Vulnerability>(ViewVulnerabilityDetails);
        BackCommand = ReactiveCommand.Create(GoBack);
    }
    
    public void OnNavigatedTo(object parameter)
    {
        if (parameter is Guid scanId)
        {
            _ = LoadScanResultAsync(scanId);
        }
    }
    
    public void OnNavigatedFrom()
    {
        // Nothing to do
    }
    
    private void Refresh()
    {
        if (ScanResult != null)
        {
            _ = LoadScanResultAsync(ScanResult.Id);
        }
    }
    
    private void ExportReport()
    {
        // Export the report
    }
    
    private void ShareReport()
    {
        // Share the report
    }
    
    private void ViewVulnerabilityDetails(Vulnerability vulnerability)
    {
        SelectedVulnerability = vulnerability;
        // Show vulnerability details
    }
    
    private void GoBack()
    {
        // Navigate back
    }
    
    private async Task LoadScanResultAsync(Guid scanId)
    {
        IsLoading = true;
        StatusMessage = "Loading scan result...";
        
        try
        {
            if (_scanResultRepository != null)
            {
                var scanResult = await _scanResultRepository.GetByIdAsync(scanId);
                if (scanResult != null)
                {
                    ScanResult = scanResult;
                    
                    // Load vulnerabilities
                    Vulnerabilities.Clear();
                    foreach (var vulnerability in scanResult.Vulnerabilities)
                    {
                        Vulnerabilities.Add(vulnerability);
                    }
                    
                    StatusMessage = $"Loaded scan result for {scanResult.TargetUrl}";
                }
                else
                {
                    StatusMessage = "Scan result not found";
                }
            }
            else
            {
                StatusMessage = "Database not available";
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error loading scan result: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }
}