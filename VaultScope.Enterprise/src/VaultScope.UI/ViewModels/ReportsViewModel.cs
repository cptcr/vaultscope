using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Reactive;
using System.Reactive.Linq;
using System.Threading.Tasks;
using Avalonia.Platform.Storage;
using ReactiveUI;
using VaultScope.Core.Models;
using VaultScope.Core.Services;
using VaultScope.Infrastructure.Data.Repositories;
using VaultScope.UI.Services;

namespace VaultScope.UI.ViewModels;

public class ReportsViewModel : ViewModelBase
{
    private readonly IScanResultRepository _scanResultRepository;
    private readonly IReportGenerator _reportGenerator;
    private readonly INotificationService _notificationService;
    private readonly INavigationService _navigationService;
    
    private ObservableCollection<ReportItemViewModel> _reports = new();
    private ReportItemViewModel? _selectedReport;
    private string _searchQuery = string.Empty;
    private ReportSortOption _sortOption = ReportSortOption.DateDescending;
    private ReportFilterOption _filterOption = ReportFilterOption.All;
    private bool _isLoading;
    private int _totalReports;
    private int _filteredReports;
    
    public ReportsViewModel()
    {
        // Design-time constructor
        _scanResultRepository = null!;
        _reportGenerator = null!;
        _notificationService = null!;
        _navigationService = null!;
        LoadDesignTimeData();
    }
    
    public ReportsViewModel(
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
        RefreshCommand = ReactiveCommand.CreateFromTask(LoadReportsAsync);
        ViewReportCommand = ReactiveCommand.Create<ReportItemViewModel>(ViewReport);
        ExportReportCommand = ReactiveCommand.CreateFromTask<ReportItemViewModel>(ExportReportAsync);
        DeleteReportCommand = ReactiveCommand.CreateFromTask<ReportItemViewModel>(DeleteReportAsync);
        ExportAllCommand = ReactiveCommand.CreateFromTask(ExportAllReportsAsync);
        
        // Set up reactive filters
        this.WhenAnyValue(
                x => x.SearchQuery,
                x => x.SortOption,
                x => x.FilterOption)
            .Throttle(TimeSpan.FromMilliseconds(300))
            .ObserveOn(RxApp.MainThreadScheduler)
            .Subscribe(async _ => await ApplyFiltersAsync());
        
        // Load reports on initialization
        Observable.StartAsync(LoadReportsAsync);
    }
    
    #region Properties
    
    public ObservableCollection<ReportItemViewModel> Reports
    {
        get => _reports;
        set => this.RaiseAndSetIfChanged(ref _reports, value);
    }
    
    public ReportItemViewModel? SelectedReport
    {
        get => _selectedReport;
        set => this.RaiseAndSetIfChanged(ref _selectedReport, value);
    }
    
    public string SearchQuery
    {
        get => _searchQuery;
        set => this.RaiseAndSetIfChanged(ref _searchQuery, value);
    }
    
    public ReportSortOption SortOption
    {
        get => _sortOption;
        set => this.RaiseAndSetIfChanged(ref _sortOption, value);
    }
    
    public ReportFilterOption FilterOption
    {
        get => _filterOption;
        set => this.RaiseAndSetIfChanged(ref _filterOption, value);
    }
    
    public bool IsLoading
    {
        get => _isLoading;
        set => this.RaiseAndSetIfChanged(ref _isLoading, value);
    }
    
    public int TotalReports
    {
        get => _totalReports;
        set => this.RaiseAndSetIfChanged(ref _totalReports, value);
    }
    
    public int FilteredReports
    {
        get => _filteredReports;
        set => this.RaiseAndSetIfChanged(ref _filteredReports, value);
    }
    
    #endregion
    
    #region Commands
    
    public ReactiveCommand<Unit, Unit> RefreshCommand { get; }
    public ReactiveCommand<ReportItemViewModel, Unit> ViewReportCommand { get; }
    public ReactiveCommand<ReportItemViewModel, Unit> ExportReportCommand { get; }
    public ReactiveCommand<ReportItemViewModel, Unit> DeleteReportCommand { get; }
    public ReactiveCommand<Unit, Unit> ExportAllCommand { get; }
    
    #endregion
    
    #region Methods
    
    private async Task LoadReportsAsync()
    {
        try
        {
            IsLoading = true;
            
            var scanResults = await _scanResultRepository.GetAllAsync();
            var reportItems = scanResults.Select(CreateReportItem).ToList();
            
            Reports = new ObservableCollection<ReportItemViewModel>(reportItems);
            TotalReports = Reports.Count;
            
            await ApplyFiltersAsync();
        }
        catch (Exception ex)
        {
            _notificationService.Show("Error", $"Failed to load reports: {ex.Message}", NotificationType.Error);
        }
        finally
        {
            IsLoading = false;
        }
    }
    
    private ReportItemViewModel CreateReportItem(ScanResult scanResult)
    {
        return new ReportItemViewModel
        {
            Id = scanResult.Id,
            TargetUrl = scanResult.TargetUrl,
            ScanDate = scanResult.StartTime,
            Duration = scanResult.EndTime - scanResult.StartTime,
            VulnerabilityCount = scanResult.Vulnerabilities.Count,
            CriticalCount = scanResult.Vulnerabilities.Count(v => v.Severity == VulnerabilitySeverity.Critical),
            HighCount = scanResult.Vulnerabilities.Count(v => v.Severity == VulnerabilitySeverity.High),
            MediumCount = scanResult.Vulnerabilities.Count(v => v.Severity == VulnerabilitySeverity.Medium),
            LowCount = scanResult.Vulnerabilities.Count(v => v.Severity == VulnerabilitySeverity.Low),
            SecurityScore = scanResult.SecurityScore?.OverallScore ?? 0,
            Status = scanResult.Status,
            HasReport = true // Assume report is generated for all completed scans
        };
    }
    
    private async Task ApplyFiltersAsync()
    {
        await Task.Run(() =>
        {
            var filtered = Reports.AsEnumerable();
            
            // Apply search filter
            if (!string.IsNullOrWhiteSpace(SearchQuery))
            {
                var query = SearchQuery.ToLowerInvariant();
                filtered = filtered.Where(r => 
                    r.TargetUrl.ToLowerInvariant().Contains(query) ||
                    r.VulnerabilityCount.ToString().Contains(query));
            }
            
            // Apply severity filter
            filtered = FilterOption switch
            {
                ReportFilterOption.Critical => filtered.Where(r => r.CriticalCount > 0),
                ReportFilterOption.High => filtered.Where(r => r.HighCount > 0),
                ReportFilterOption.Medium => filtered.Where(r => r.MediumCount > 0),
                ReportFilterOption.Low => filtered.Where(r => r.LowCount > 0),
                ReportFilterOption.Clean => filtered.Where(r => r.VulnerabilityCount == 0),
                _ => filtered
            };
            
            // Apply sorting
            filtered = SortOption switch
            {
                ReportSortOption.DateDescending => filtered.OrderByDescending(r => r.ScanDate),
                ReportSortOption.DateAscending => filtered.OrderBy(r => r.ScanDate),
                ReportSortOption.ScoreDescending => filtered.OrderByDescending(r => r.SecurityScore),
                ReportSortOption.ScoreAscending => filtered.OrderBy(r => r.SecurityScore),
                ReportSortOption.VulnerabilitiesDescending => filtered.OrderByDescending(r => r.VulnerabilityCount),
                ReportSortOption.VulnerabilitiesAscending => filtered.OrderBy(r => r.VulnerabilityCount),
                _ => filtered.OrderByDescending(r => r.ScanDate)
            };
            
            // Update filtered reports
            var filteredList = filtered.ToList();
            FilteredReports = filteredList.Count;
            
            // Update UI on main thread
            Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                Reports.Clear();
                foreach (var report in filteredList)
                {
                    Reports.Add(report);
                }
            });
        });
    }
    
    private void ViewReport(ReportItemViewModel report)
    {
        _navigationService.NavigateTo<ScanResultDetailViewModel>(report.Id);
    }
    
    private async Task ExportReportAsync(ReportItemViewModel report)
    {
        try
        {
            // Get scan result
            var scanResult = await _scanResultRepository.GetByIdAsync(report.Id);
            if (scanResult == null)
            {
                _notificationService.Show("Error", "Report not found", NotificationType.Error);
                return;
            }
            
            // Show export options dialog
            var exportFormat = await ShowExportFormatDialog();
            if (exportFormat == null) return;
            
            // Get save location
            var saveLocation = await GetSaveLocation($"VaultScope_Report_{report.ScanDate:yyyyMMdd_HHmmss}", exportFormat.Value);
            if (saveLocation == null) return;
            
            // Generate report
            IsLoading = true;
            byte[] reportData = exportFormat.Value switch
            {
                ExportFormat.Html => await _reportGenerator.GenerateHtmlReportAsync(scanResult),
                ExportFormat.Json => await _reportGenerator.GenerateJsonReportAsync(scanResult),
                ExportFormat.Pdf => await _reportGenerator.GeneratePdfReportAsync(scanResult),
                _ => throw new NotSupportedException($"Export format {exportFormat} is not supported")
            };
            
            // Save file
            await File.WriteAllBytesAsync(saveLocation, reportData);
            
            _notificationService.Show("Export Complete", $"Report exported to {Path.GetFileName(saveLocation)}", NotificationType.Success);
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
    
    private async Task DeleteReportAsync(ReportItemViewModel report)
    {
        var confirm = await _notificationService.ShowConfirmationAsync(
            "Delete Report",
            $"Are you sure you want to delete the report for {report.TargetUrl}?");
        
        if (!confirm) return;
        
        try
        {
            await _scanResultRepository.DeleteAsync(report.Id);
            Reports.Remove(report);
            TotalReports = Reports.Count;
            
            _notificationService.Show("Report Deleted", "The report has been deleted successfully", NotificationType.Success);
        }
        catch (Exception ex)
        {
            _notificationService.Show("Delete Error", ex.Message, NotificationType.Error);
        }
    }
    
    private async Task ExportAllReportsAsync()
    {
        if (!Reports.Any())
        {
            _notificationService.Show("No Reports", "There are no reports to export", NotificationType.Information);
            return;
        }
        
        var confirm = await _notificationService.ShowConfirmationAsync(
            "Export All Reports",
            $"Export all {FilteredReports} reports to a single archive?");
        
        if (!confirm) return;
        
        try
        {
            IsLoading = true;
            
            // Create temporary directory for reports
            var tempDir = Path.Combine(Path.GetTempPath(), $"VaultScope_Export_{DateTime.Now:yyyyMMdd_HHmmss}");
            Directory.CreateDirectory(tempDir);
            
            // Export each report
            foreach (var report in Reports)
            {
                var scanResult = await _scanResultRepository.GetByIdAsync(report.Id);
                if (scanResult == null) continue;
                
                var htmlReport = await _reportGenerator.GenerateHtmlReportAsync(scanResult);
                var fileName = $"{scanResult.TargetUrl.Replace("://", "_").Replace("/", "_")}_{scanResult.StartTime:yyyyMMdd_HHmmss}.html";
                await File.WriteAllBytesAsync(Path.Combine(tempDir, fileName), htmlReport);
            }
            
            // Create archive
            var archivePath = await GetSaveLocation($"VaultScope_Reports_{DateTime.Now:yyyyMMdd_HHmmss}", ExportFormat.Zip);
            if (archivePath == null)
            {
                Directory.Delete(tempDir, true);
                return;
            }
            
            System.IO.Compression.ZipFile.CreateFromDirectory(tempDir, archivePath);
            Directory.Delete(tempDir, true);
            
            _notificationService.Show("Export Complete", $"All reports exported to {Path.GetFileName(archivePath)}", NotificationType.Success);
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
    
    private async Task<ExportFormat?> ShowExportFormatDialog()
    {
        // In a real implementation, this would show a dialog
        // For now, return HTML as default
        return await Task.FromResult(ExportFormat.Html);
    }
    
    private async Task<string?> GetSaveLocation(string defaultFileName, ExportFormat format)
    {
        // In a real implementation, this would show a file save dialog
        // For now, return a default path
        var extension = format switch
        {
            ExportFormat.Html => ".html",
            ExportFormat.Json => ".json",
            ExportFormat.Pdf => ".pdf",
            ExportFormat.Zip => ".zip",
            _ => ".html"
        };
        
        var documentsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var filePath = Path.Combine(documentsPath, "VaultScope", $"{defaultFileName}{extension}");
        
        Directory.CreateDirectory(Path.GetDirectoryName(filePath)!);
        return await Task.FromResult(filePath);
    }
    
    private void LoadDesignTimeData()
    {
        Reports = new ObservableCollection<ReportItemViewModel>
        {
            new()
            {
                Id = Guid.NewGuid(),
                TargetUrl = "http://localhost:3000/api",
                ScanDate = DateTime.Now.AddHours(-2),
                Duration = TimeSpan.FromMinutes(5),
                VulnerabilityCount = 12,
                CriticalCount = 2,
                HighCount = 3,
                MediumCount = 4,
                LowCount = 3,
                SecurityScore = 68.5,
                Status = ScanStatus.Completed,
                HasReport = true
            },
            new()
            {
                Id = Guid.NewGuid(),
                TargetUrl = "http://localhost:8080",
                ScanDate = DateTime.Now.AddDays(-1),
                Duration = TimeSpan.FromMinutes(3),
                VulnerabilityCount = 5,
                CriticalCount = 0,
                HighCount = 1,
                MediumCount = 2,
                LowCount = 2,
                SecurityScore = 85.0,
                Status = ScanStatus.Completed,
                HasReport = true
            },
            new()
            {
                Id = Guid.NewGuid(),
                TargetUrl = "http://localhost:5000/graphql",
                ScanDate = DateTime.Now.AddDays(-2),
                Duration = TimeSpan.FromMinutes(8),
                VulnerabilityCount = 0,
                CriticalCount = 0,
                HighCount = 0,
                MediumCount = 0,
                LowCount = 0,
                SecurityScore = 100.0,
                Status = ScanStatus.Completed,
                HasReport = true
            }
        };
        
        TotalReports = Reports.Count;
        FilteredReports = Reports.Count;
    }
    
    #endregion
}

public class ReportItemViewModel
{
    public Guid Id { get; set; }
    public string TargetUrl { get; set; } = string.Empty;
    public DateTime ScanDate { get; set; }
    public TimeSpan Duration { get; set; }
    public int VulnerabilityCount { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public double SecurityScore { get; set; }
    public ScanStatus Status { get; set; }
    public bool HasReport { get; set; }
}

public enum ReportSortOption
{
    DateDescending,
    DateAscending,
    ScoreDescending,
    ScoreAscending,
    VulnerabilitiesDescending,
    VulnerabilitiesAscending
}

public enum ReportFilterOption
{
    All,
    Critical,
    High,
    Medium,
    Low,
    Clean
}

public enum ExportFormat
{
    Html,
    Json,
    Pdf,
    Zip
}