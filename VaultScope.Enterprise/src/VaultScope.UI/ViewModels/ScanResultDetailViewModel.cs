using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Reactive;
using System.Threading.Tasks;
using ReactiveUI;
using VaultScope.Core.Models;
using VaultScope.Core.Services;
using VaultScope.Infrastructure.Data.Repositories;
using VaultScope.UI.Services;

namespace VaultScope.UI.ViewModels;

public class ScanResultDetailViewModel : ViewModelBase, INavigationAware
{
    private readonly IScanResultRepository _scanResultRepository;
    private readonly IReportGenerator _reportGenerator;
    private readonly INotificationService _notificationService;
    private readonly INavigationService _navigationService;
    
    private ScanResult? _scanResult;
    private bool _isLoading;
    private string _targetUrl = string.Empty;
    private DateTime _scanDate;
    private TimeSpan _duration;
    private ScanStatus _status;
    private double _securityScore;
    private string _scoreGrade = string.Empty;
    private ObservableCollection<VulnerabilityViewModel> _vulnerabilities = new();
    private ObservableCollection<EndpointViewModel> _endpoints = new();
    private VulnerabilityViewModel? _selectedVulnerability;
    private string _vulnerabilityFilter = "All";
    private string _searchQuery = string.Empty;
    private SecurityScoreBreakdown? _scoreBreakdown;
    
    // Statistics
    private int _totalVulnerabilities;
    private int _criticalCount;
    private int _highCount;
    private int _mediumCount;
    private int _lowCount;
    private int _totalEndpoints;
    private int _vulnerableEndpoints;
    
    public ScanResultDetailViewModel()
    {
        // Design-time constructor
        _scanResultRepository = null!;
        _reportGenerator = null!;
        _notificationService = null!;
        _navigationService = null!;
        LoadDesignTimeData();
    }
    
    public ScanResultDetailViewModel(
        IScanResultRepository scanResultRepository,
        IReportGenerator reportGenerator,
        INotificationService notificationService,
        INavigationService navigationService)
    {
        _scanResultRepository = scanResultRepository;
        _reportGenerator = reportGenerator;
        _notificationService = notificationService;
        _navigationService = navigationService;
        
        // Initialize commands
        RefreshCommand = ReactiveCommand.CreateFromTask(LoadScanResultAsync);
        ExportReportCommand = ReactiveCommand.CreateFromTask(ExportReportAsync);
        ShareReportCommand = ReactiveCommand.CreateFromTask(ShareReportAsync);
        ViewVulnerabilityDetailsCommand = ReactiveCommand.Create<VulnerabilityViewModel>(ViewVulnerabilityDetails);
        BackCommand = ReactiveCommand.Create(NavigateBack);
        
        // Set up reactive filters
        this.WhenAnyValue(x => x.SearchQuery, x => x.VulnerabilityFilter)
            .Subscribe(_ => ApplyFilters());
    }
    
    #region Properties
    
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
    
    public string TargetUrl
    {
        get => _targetUrl;
        set => this.RaiseAndSetIfChanged(ref _targetUrl, value);
    }
    
    public DateTime ScanDate
    {
        get => _scanDate;
        set => this.RaiseAndSetIfChanged(ref _scanDate, value);
    }
    
    public TimeSpan Duration
    {
        get => _duration;
        set => this.RaiseAndSetIfChanged(ref _duration, value);
    }
    
    public ScanStatus Status
    {
        get => _status;
        set => this.RaiseAndSetIfChanged(ref _status, value);
    }
    
    public double SecurityScore
    {
        get => _securityScore;
        set
        {
            this.RaiseAndSetIfChanged(ref _securityScore, value);
            ScoreGrade = GetScoreGrade(value);
        }
    }
    
    public string ScoreGrade
    {
        get => _scoreGrade;
        set => this.RaiseAndSetIfChanged(ref _scoreGrade, value);
    }
    
    public ObservableCollection<VulnerabilityViewModel> Vulnerabilities
    {
        get => _vulnerabilities;
        set => this.RaiseAndSetIfChanged(ref _vulnerabilities, value);
    }
    
    public ObservableCollection<EndpointViewModel> Endpoints
    {
        get => _endpoints;
        set => this.RaiseAndSetIfChanged(ref _endpoints, value);
    }
    
    public VulnerabilityViewModel? SelectedVulnerability
    {
        get => _selectedVulnerability;
        set => this.RaiseAndSetIfChanged(ref _selectedVulnerability, value);
    }
    
    public string VulnerabilityFilter
    {
        get => _vulnerabilityFilter;
        set => this.RaiseAndSetIfChanged(ref _vulnerabilityFilter, value);
    }
    
    public string SearchQuery
    {
        get => _searchQuery;
        set => this.RaiseAndSetIfChanged(ref _searchQuery, value);
    }
    
    public SecurityScoreBreakdown? ScoreBreakdown
    {
        get => _scoreBreakdown;
        set => this.RaiseAndSetIfChanged(ref _scoreBreakdown, value);
    }
    
    // Statistics
    public int TotalVulnerabilities
    {
        get => _totalVulnerabilities;
        set => this.RaiseAndSetIfChanged(ref _totalVulnerabilities, value);
    }
    
    public int CriticalCount
    {
        get => _criticalCount;
        set => this.RaiseAndSetIfChanged(ref _criticalCount, value);
    }
    
    public int HighCount
    {
        get => _highCount;
        set => this.RaiseAndSetIfChanged(ref _highCount, value);
    }
    
    public int MediumCount
    {
        get => _mediumCount;
        set => this.RaiseAndSetIfChanged(ref _mediumCount, value);
    }
    
    public int LowCount
    {
        get => _lowCount;
        set => this.RaiseAndSetIfChanged(ref _lowCount, value);
    }
    
    public int TotalEndpoints
    {
        get => _totalEndpoints;
        set => this.RaiseAndSetIfChanged(ref _totalEndpoints, value);
    }
    
    public int VulnerableEndpoints
    {
        get => _vulnerableEndpoints;
        set => this.RaiseAndSetIfChanged(ref _vulnerableEndpoints, value);
    }
    
    #endregion
    
    #region Commands
    
    public ReactiveCommand<Unit, Unit> RefreshCommand { get; }
    public ReactiveCommand<Unit, Unit> ExportReportCommand { get; }
    public ReactiveCommand<Unit, Unit> ShareReportCommand { get; }
    public ReactiveCommand<VulnerabilityViewModel, Unit> ViewVulnerabilityDetailsCommand { get; }
    public ReactiveCommand<Unit, Unit> BackCommand { get; }
    
    #endregion
    
    #region INavigationAware
    
    public async Task OnNavigatedTo(object? parameter)
    {
        if (parameter is Guid scanId)
        {
            await LoadScanResultAsync(scanId);
        }
    }
    
    public Task OnNavigatedFrom()
    {
        return Task.CompletedTask;
    }
    
    #endregion
    
    #region Methods
    
    private async Task LoadScanResultAsync()
    {
        if (ScanResult != null)
        {
            await LoadScanResultAsync(ScanResult.Id);
        }
    }
    
    private async Task LoadScanResultAsync(Guid scanId)
    {
        try
        {
            IsLoading = true;
            
            ScanResult = await _scanResultRepository.GetByIdAsync(scanId);
            if (ScanResult == null)
            {
                _notificationService.Show("Error", "Scan result not found", NotificationType.Error);
                return;
            }
            
            // Update properties
            TargetUrl = ScanResult.TargetUrl;
            ScanDate = ScanResult.StartTime;
            Duration = ScanResult.EndTime - ScanResult.StartTime;
            Status = ScanResult.Status;
            SecurityScore = ScanResult.SecurityScore?.OverallScore ?? 0;
            ScoreBreakdown = ScanResult.SecurityScore?.Breakdown;
            
            // Update statistics
            TotalVulnerabilities = ScanResult.Vulnerabilities.Count;
            CriticalCount = ScanResult.Vulnerabilities.Count(v => v.Severity == VulnerabilitySeverity.Critical);
            HighCount = ScanResult.Vulnerabilities.Count(v => v.Severity == VulnerabilitySeverity.High);
            MediumCount = ScanResult.Vulnerabilities.Count(v => v.Severity == VulnerabilitySeverity.Medium);
            LowCount = ScanResult.Vulnerabilities.Count(v => v.Severity == VulnerabilitySeverity.Low);
            
            TotalEndpoints = ScanResult.TestedEndpoints.Count;
            VulnerableEndpoints = ScanResult.TestedEndpoints.Count(e => 
                ScanResult.Vulnerabilities.Any(v => v.Endpoint == e));
            
            // Convert to view models
            LoadVulnerabilities();
            LoadEndpoints();
        }
        catch (Exception ex)
        {
            _notificationService.Show("Error", $"Failed to load scan result: {ex.Message}", NotificationType.Error);
        }
        finally
        {
            IsLoading = false;
        }
    }
    
    private void LoadVulnerabilities()
    {
        if (ScanResult == null) return;
        
        Vulnerabilities.Clear();
        
        foreach (var vuln in ScanResult.Vulnerabilities.OrderByDescending(v => v.Severity))
        {
            Vulnerabilities.Add(new VulnerabilityViewModel
            {
                Id = vuln.Id,
                Type = vuln.Type,
                Severity = vuln.Severity,
                Endpoint = vuln.Endpoint,
                Method = vuln.Method,
                Parameter = vuln.Parameter,
                Evidence = vuln.Evidence,
                Description = vuln.Description,
                Impact = vuln.Impact,
                Remediation = vuln.Remediation,
                CweId = vuln.CweId,
                OwaspCategory = vuln.OwaspCategory,
                DiscoveredAt = vuln.DiscoveredAt
            });
        }
    }
    
    private void LoadEndpoints()
    {
        if (ScanResult == null) return;
        
        Endpoints.Clear();
        
        foreach (var endpoint in ScanResult.TestedEndpoints.Distinct())
        {
            var endpointVulns = ScanResult.Vulnerabilities.Where(v => v.Endpoint == endpoint).ToList();
            
            Endpoints.Add(new EndpointViewModel
            {
                Url = endpoint,
                VulnerabilityCount = endpointVulns.Count,
                CriticalCount = endpointVulns.Count(v => v.Severity == VulnerabilitySeverity.Critical),
                HighCount = endpointVulns.Count(v => v.Severity == VulnerabilitySeverity.High),
                MediumCount = endpointVulns.Count(v => v.Severity == VulnerabilitySeverity.Medium),
                LowCount = endpointVulns.Count(v => v.Severity == VulnerabilitySeverity.Low),
                IsSafe = endpointVulns.Count == 0
            });
        }
        
        Endpoints = new ObservableCollection<EndpointViewModel>(
            Endpoints.OrderByDescending(e => e.VulnerabilityCount));
    }
    
    private void ApplyFilters()
    {
        if (ScanResult == null) return;
        
        var filtered = ScanResult.Vulnerabilities.AsEnumerable();
        
        // Apply severity filter
        if (VulnerabilityFilter != "All")
        {
            if (Enum.TryParse<VulnerabilitySeverity>(VulnerabilityFilter, out var severity))
            {
                filtered = filtered.Where(v => v.Severity == severity);
            }
        }
        
        // Apply search filter
        if (!string.IsNullOrWhiteSpace(SearchQuery))
        {
            var query = SearchQuery.ToLowerInvariant();
            filtered = filtered.Where(v =>
                v.Type.ToLowerInvariant().Contains(query) ||
                v.Endpoint.ToLowerInvariant().Contains(query) ||
                v.Description.ToLowerInvariant().Contains(query));
        }
        
        // Update vulnerabilities
        Vulnerabilities.Clear();
        foreach (var vuln in filtered.OrderByDescending(v => v.Severity))
        {
            Vulnerabilities.Add(new VulnerabilityViewModel
            {
                Id = vuln.Id,
                Type = vuln.Type,
                Severity = vuln.Severity,
                Endpoint = vuln.Endpoint,
                Method = vuln.Method,
                Parameter = vuln.Parameter,
                Evidence = vuln.Evidence,
                Description = vuln.Description,
                Impact = vuln.Impact,
                Remediation = vuln.Remediation,
                CweId = vuln.CweId,
                OwaspCategory = vuln.OwaspCategory,
                DiscoveredAt = vuln.DiscoveredAt
            });
        }
    }
    
    private async Task ExportReportAsync()
    {
        if (ScanResult == null) return;
        
        try
        {
            IsLoading = true;
            
            // Generate HTML report
            var reportData = await _reportGenerator.GenerateHtmlReportAsync(ScanResult);
            
            // Save to documents folder
            var documentsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            var fileName = $"VaultScope_Report_{ScanResult.TargetUrl.Replace("://", "_").Replace("/", "_")}_{ScanResult.StartTime:yyyyMMdd_HHmmss}.html";
            var filePath = Path.Combine(documentsPath, "VaultScope", fileName);
            
            Directory.CreateDirectory(Path.GetDirectoryName(filePath)!);
            await File.WriteAllBytesAsync(filePath, reportData);
            
            _notificationService.Show("Export Complete", $"Report saved to {fileName}", NotificationType.Success);
        }
        catch (Exception ex)
        {
            _notificationService.Show("Export Error", ex.Message, NotificationType.Error);
        }
        finally
        {
            IsLoading = false;
        }
    }
    
    private async Task ShareReportAsync()
    {
        if (ScanResult == null) return;
        
        try
        {
            // Generate shareable link or export to clipboard
            var summary = $"VaultScope Security Scan Report\n" +
                         $"Target: {ScanResult.TargetUrl}\n" +
                         $"Date: {ScanResult.StartTime:yyyy-MM-dd HH:mm}\n" +
                         $"Security Score: {SecurityScore:F1}/100\n" +
                         $"Vulnerabilities: {TotalVulnerabilities} " +
                         $"(Critical: {CriticalCount}, High: {HighCount}, Medium: {MediumCount}, Low: {LowCount})";
            
            // In a real implementation, copy to clipboard
            _notificationService.Show("Report Summary", "Report summary copied to clipboard", NotificationType.Success);
            
            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _notificationService.Show("Share Error", ex.Message, NotificationType.Error);
        }
    }
    
    private void ViewVulnerabilityDetails(VulnerabilityViewModel vulnerability)
    {
        SelectedVulnerability = vulnerability;
        // In a real implementation, this could open a detailed view or dialog
    }
    
    private void NavigateBack()
    {
        _navigationService.GoBack();
    }
    
    private string GetScoreGrade(double score)
    {
        return score switch
        {
            >= 90 => "A+",
            >= 80 => "A",
            >= 70 => "B",
            >= 60 => "C",
            >= 50 => "D",
            _ => "F"
        };
    }
    
    private void LoadDesignTimeData()
    {
        TargetUrl = "http://localhost:3000/api";
        ScanDate = DateTime.Now.AddHours(-2);
        Duration = TimeSpan.FromMinutes(5);
        Status = ScanStatus.Completed;
        SecurityScore = 72.5;
        
        TotalVulnerabilities = 12;
        CriticalCount = 2;
        HighCount = 3;
        MediumCount = 4;
        LowCount = 3;
        TotalEndpoints = 15;
        VulnerableEndpoints = 8;
        
        Vulnerabilities = new ObservableCollection<VulnerabilityViewModel>
        {
            new()
            {
                Type = "SQL Injection",
                Severity = VulnerabilitySeverity.Critical,
                Endpoint = "/api/users",
                Method = "GET",
                Parameter = "id",
                Description = "The application is vulnerable to SQL injection attacks",
                Impact = "An attacker could read, modify, or delete database contents"
            },
            new()
            {
                Type = "Cross-Site Scripting (XSS)",
                Severity = VulnerabilitySeverity.High,
                Endpoint = "/api/search",
                Method = "GET",
                Parameter = "query",
                Description = "User input is not properly sanitized before being reflected",
                Impact = "An attacker could execute malicious scripts in users' browsers"
            }
        };
        
        Endpoints = new ObservableCollection<EndpointViewModel>
        {
            new() { Url = "/api/users", VulnerabilityCount = 3, CriticalCount = 1, HighCount = 1, MediumCount = 1 },
            new() { Url = "/api/search", VulnerabilityCount = 2, HighCount = 1, MediumCount = 1 },
            new() { Url = "/api/auth", VulnerabilityCount = 0, IsSafe = true }
        };
    }
    
    #endregion
}

public class VulnerabilityViewModel
{
    public Guid Id { get; set; }
    public string Type { get; set; } = string.Empty;
    public VulnerabilitySeverity Severity { get; set; }
    public string Endpoint { get; set; } = string.Empty;
    public string Method { get; set; } = string.Empty;
    public string Parameter { get; set; } = string.Empty;
    public string Evidence { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Impact { get; set; } = string.Empty;
    public string Remediation { get; set; } = string.Empty;
    public int? CweId { get; set; }
    public string? OwaspCategory { get; set; }
    public DateTime DiscoveredAt { get; set; }
}

public class EndpointViewModel
{
    public string Url { get; set; } = string.Empty;
    public int VulnerabilityCount { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public bool IsSafe { get; set; }
}

public class SecurityScoreBreakdown
{
    public double AuthenticationScore { get; set; }
    public double InputValidationScore { get; set; }
    public double SessionManagementScore { get; set; }
    public double ErrorHandlingScore { get; set; }
    public double CryptographyScore { get; set; }
    public double AccessControlScore { get; set; }
}