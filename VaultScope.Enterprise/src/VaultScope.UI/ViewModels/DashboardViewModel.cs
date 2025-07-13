using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Reactive;
using System.Threading.Tasks;
using ReactiveUI;
using VaultScope.Core.Constants;
using VaultScope.Core.Models;
using VaultScope.Infrastructure.Data.Repositories;

namespace VaultScope.UI.ViewModels;

public class DashboardViewModel : ViewModelBase
{
    private readonly IScanResultRepository? _scanResultRepository;
    private bool _isLoading;
    private string _statusMessage = "Ready";
    private int _totalScans;
    private int _totalVulnerabilities;
    private int _criticalVulnerabilities;
    private double _averageSecurityScore;
    
    public bool IsLoading
    {
        get => _isLoading;
        set => this.RaiseAndSetIfChanged(ref _isLoading, value);
    }
    
    public string StatusMessage
    {
        get => _statusMessage;
        set => this.RaiseAndSetIfChanged(ref _statusMessage, value);
    }

    
    public int TotalScans
    {
        get => _totalScans;
        set => this.RaiseAndSetIfChanged(ref _totalScans, value);
    }
    
    public int TotalVulnerabilities
    {
        get => _totalVulnerabilities;
        set => this.RaiseAndSetIfChanged(ref _totalVulnerabilities, value);
    }
    
    public int CriticalVulnerabilities
    {
        get => _criticalVulnerabilities;
        set => this.RaiseAndSetIfChanged(ref _criticalVulnerabilities, value);
    }
    
    public double AverageSecurityScore
    {
        get => _averageSecurityScore;
        set => this.RaiseAndSetIfChanged(ref _averageSecurityScore, value);
    }
    
    public ObservableCollection<ScanResult> RecentScans { get; } = new();
    public ObservableCollection<Vulnerability> RecentVulnerabilities { get; } = new();
    
    // Commands
    public ReactiveCommand<Unit, Unit> RefreshCommand { get; }
    public ReactiveCommand<ScanResult, Unit> ViewScanDetailsCommand { get; }
    public ReactiveCommand<Unit, Unit> StartNewScanCommand { get; }
    
    public DashboardViewModel(IScanResultRepository? scanResultRepository = null)
    {
        _scanResultRepository = scanResultRepository;
        
        RefreshCommand = ReactiveCommand.Create(Refresh);
        ViewScanDetailsCommand = ReactiveCommand.Create<ScanResult>(ViewScanDetails);
        StartNewScanCommand = ReactiveCommand.Create(StartNewScan);
        
        LoadDashboardData();
    }
    
    private async void Refresh()
    {
        await LoadDashboardDataAsync();
    }
    
    private void ViewScanDetails(ScanResult scan)
    {
        StatusMessage = $"Viewing scan details for {scan.TargetUrl}";
    }
    
    private void StartNewScan()
    {
        StatusMessage = "Navigate to scanner to start a new scan";
    }
    
    private async void LoadDashboardData()
    {
        await LoadDashboardDataAsync();
    }
    
    private async Task LoadDashboardDataAsync()
    {
        IsLoading = true;
        StatusMessage = "Loading dashboard data...";
        
        try
        {
            if (_scanResultRepository != null)
            {
                // Load real data from repository
                var recentScans = await _scanResultRepository.GetRecentScansAsync(10);
                RecentScans.Clear();
                foreach (var scan in recentScans)
                {
                    RecentScans.Add(scan);
                }
                
                var allScans = await _scanResultRepository.GetAllAsync();
                TotalScans = allScans.Count();
                TotalVulnerabilities = allScans.SelectMany(s => s.Vulnerabilities).Count();
                CriticalVulnerabilities = allScans.SelectMany(s => s.Vulnerabilities)
                    .Count(v => v.Severity == VulnerabilitySeverity.Critical);
                AverageSecurityScore = allScans.Any() ? allScans.Average(s => s.SecurityScore.OverallScore) : 0;
                
                // Load recent vulnerabilities
                RecentVulnerabilities.Clear();
                var recentVulns = allScans.SelectMany(s => s.Vulnerabilities)
                    .OrderByDescending(v => v.Id)
                    .Take(10);
                foreach (var vuln in recentVulns)
                {
                    RecentVulnerabilities.Add(vuln);
                }
            }
            else
            {
                // No repository available - show message
                StatusMessage = "Database not available. Use 'Load Example Data' to simulate.";
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error loading dashboard data: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
            if (_scanResultRepository != null)
            {
                StatusMessage = $"Dashboard loaded - {TotalScans} scans, {TotalVulnerabilities} vulnerabilities";
            }
        }
    }
    
}