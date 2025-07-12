using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Reactive;
using System.Reactive.Linq;
using System.Threading.Tasks;
using ReactiveUI;
using VaultScope.Core.Models;
using VaultScope.Infrastructure.Data.Repositories;

namespace VaultScope.UI.ViewModels;

public class DashboardViewModel : ViewModelBase
{
    private readonly IScanResultRepository _scanResultRepository;
    
    private int _totalScans;
    private int _criticalVulnerabilities;
    private int _highVulnerabilities;
    private int _mediumVulnerabilities;
    private int _lowVulnerabilities;
    private double _averageSecurityScore;
    private ObservableCollection<RecentScanViewModel> _recentScans = new();
    private ObservableCollection<VulnerabilityTrendViewModel> _vulnerabilityTrends = new();
    private bool _isLoading;
    
    public DashboardViewModel()
    {
        // For design-time
        _scanResultRepository = null!;
        LoadDesignTimeData();
    }
    
    public DashboardViewModel(IScanResultRepository scanResultRepository)
    {
        _scanResultRepository = scanResultRepository;
        
        RefreshCommand = ReactiveCommand.CreateFromTask(RefreshDataAsync);
        ViewScanDetailsCommand = ReactiveCommand.Create<Guid>(ViewScanDetails);
        StartNewScanCommand = ReactiveCommand.Create(StartNewScan);
        
        // Auto-refresh every 30 seconds
        Observable.Timer(TimeSpan.Zero, TimeSpan.FromSeconds(30))
            .ObserveOn(RxApp.MainThreadScheduler)
            .Subscribe(async _ => await RefreshDataAsync());
    }
    
    public int TotalScans
    {
        get => _totalScans;
        set => this.RaiseAndSetIfChanged(ref _totalScans, value);
    }
    
    public int CriticalVulnerabilities
    {
        get => _criticalVulnerabilities;
        set => this.RaiseAndSetIfChanged(ref _criticalVulnerabilities, value);
    }
    
    public int HighVulnerabilities
    {
        get => _highVulnerabilities;
        set => this.RaiseAndSetIfChanged(ref _highVulnerabilities, value);
    }
    
    public int MediumVulnerabilities
    {
        get => _mediumVulnerabilities;
        set => this.RaiseAndSetIfChanged(ref _mediumVulnerabilities, value);
    }
    
    public int LowVulnerabilities
    {
        get => _lowVulnerabilities;
        set => this.RaiseAndSetIfChanged(ref _lowVulnerabilities, value);
    }
    
    public double AverageSecurityScore
    {
        get => _averageSecurityScore;
        set => this.RaiseAndSetIfChanged(ref _averageSecurityScore, value);
    }
    
    public ObservableCollection<RecentScanViewModel> RecentScans
    {
        get => _recentScans;
        set => this.RaiseAndSetIfChanged(ref _recentScans, value);
    }
    
    public ObservableCollection<VulnerabilityTrendViewModel> VulnerabilityTrends
    {
        get => _vulnerabilityTrends;
        set => this.RaiseAndSetIfChanged(ref _vulnerabilityTrends, value);
    }
    
    public bool IsLoading
    {
        get => _isLoading;
        set => this.RaiseAndSetIfChanged(ref _isLoading, value);
    }
    
    public ReactiveCommand<Unit, Unit> RefreshCommand { get; }
    public ReactiveCommand<Guid, Unit> ViewScanDetailsCommand { get; }
    public ReactiveCommand<Unit, Unit> StartNewScanCommand { get; }
    
    private async Task RefreshDataAsync()
    {
        IsLoading = true;
        
        try
        {
            // Get statistics
            var stats = await _scanResultRepository.GetVulnerabilityStatisticsAsync();
            TotalScans = await _scanResultRepository.GetTotalCountAsync();
            
            CriticalVulnerabilities = stats.GetValueOrDefault("Critical", 0);
            HighVulnerabilities = stats.GetValueOrDefault("High", 0);
            MediumVulnerabilities = stats.GetValueOrDefault("Medium", 0);
            LowVulnerabilities = stats.GetValueOrDefault("Low", 0);
            
            // Get recent scans
            var recentScans = await _scanResultRepository.GetRecentScansAsync(5);
            RecentScans.Clear();
            
            foreach (var scan in recentScans)
            {
                RecentScans.Add(new RecentScanViewModel
                {
                    Id = scan.Id,
                    TargetUrl = scan.TargetUrl,
                    ScanDate = scan.StartTime,
                    VulnerabilityCount = scan.Vulnerabilities.Count,
                    SecurityScore = scan.SecurityScore?.OverallScore ?? 0,
                    Status = scan.Status
                });
            }
            
            // Calculate average security score
            var scoresWithValue = recentScans
                .Where(s => s.SecurityScore != null)
                .Select(s => s.SecurityScore!.OverallScore)
                .ToList();
            
            AverageSecurityScore = scoresWithValue.Any() ? scoresWithValue.Average() : 0;
            
            // Update vulnerability trends (mock data for now)
            UpdateVulnerabilityTrends();
        }
        catch (Exception ex)
        {
            // Handle error
            App.ShowNotification("Error", $"Failed to refresh dashboard: {ex.Message}", NotificationType.Error);
        }
        finally
        {
            IsLoading = false;
        }
    }
    
    private void UpdateVulnerabilityTrends()
    {
        VulnerabilityTrends.Clear();
        
        // Mock trend data - in real app, calculate from historical data
        var random = new Random();
        for (int i = 6; i >= 0; i--)
        {
            var date = DateTime.Today.AddDays(-i);
            VulnerabilityTrends.Add(new VulnerabilityTrendViewModel
            {
                Date = date,
                Critical = random.Next(0, 5),
                High = random.Next(2, 10),
                Medium = random.Next(5, 15),
                Low = random.Next(10, 25)
            });
        }
    }
    
    private void ViewScanDetails(Guid scanId)
    {
        // Navigate to scan details
        App.ServiceProvider.GetService<INavigationService>()?.NavigateTo<ScanResultDetailViewModel>(scanId);
    }
    
    private void StartNewScan()
    {
        // Navigate to scanner
        App.ServiceProvider.GetService<INavigationService>()?.NavigateTo<ScannerViewModel>();
    }
    
    private void LoadDesignTimeData()
    {
        TotalScans = 42;
        CriticalVulnerabilities = 3;
        HighVulnerabilities = 7;
        MediumVulnerabilities = 15;
        LowVulnerabilities = 28;
        AverageSecurityScore = 72.5;
        
        RecentScans = new ObservableCollection<RecentScanViewModel>
        {
            new() { TargetUrl = "http://localhost:3000", ScanDate = DateTime.Now.AddHours(-1), VulnerabilityCount = 5, SecurityScore = 85 },
            new() { TargetUrl = "http://localhost:8080/api", ScanDate = DateTime.Now.AddHours(-3), VulnerabilityCount = 12, SecurityScore = 65 },
            new() { TargetUrl = "http://localhost:5000", ScanDate = DateTime.Now.AddDays(-1), VulnerabilityCount = 3, SecurityScore = 92 }
        };
    }
}

public class RecentScanViewModel
{
    public Guid Id { get; set; }
    public string TargetUrl { get; set; } = string.Empty;
    public DateTime ScanDate { get; set; }
    public int VulnerabilityCount { get; set; }
    public double SecurityScore { get; set; }
    public ScanStatus Status { get; set; }
}

public class VulnerabilityTrendViewModel
{
    public DateTime Date { get; set; }
    public int Critical { get; set; }
    public int High { get; set; }
    public int Medium { get; set; }
    public int Low { get; set; }
}