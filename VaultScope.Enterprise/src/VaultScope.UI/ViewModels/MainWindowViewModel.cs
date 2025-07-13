using System;
using System.Reactive;
using ReactiveUI;
using VaultScope.Core.Interfaces;
using VaultScope.Infrastructure.Data.Repositories;

namespace VaultScope.UI.ViewModels;

public class MainWindowViewModel : ViewModelBase
{
    private readonly ISecurityScanner? _securityScanner;
    private readonly IScanResultRepository? _scanResultRepository;
    private string _currentTime = DateTime.Now.ToString("HH:mm:ss");
    private ViewModelBase _currentView;
    
    public string CurrentTime
    {
        get => _currentTime;
        set => this.RaiseAndSetIfChanged(ref _currentTime, value);
    }
    
    public ViewModelBase CurrentView
    {
        get => _currentView;
        set => this.RaiseAndSetIfChanged(ref _currentView, value);
    }
    
    public ViewModelBase CurrentPage => CurrentView;
    
    // Navigation Properties
    public bool IsDashboardSelected { get; set; }
    public bool IsScannerSelected { get; set; }
    public bool IsReportsSelected { get; set; }
    public bool IsSettingsSelected { get; set; }
    
    // Status Properties
    public string StatusText { get; set; } = "Ready to scan";
    public string ConnectionStatus { get; set; } = "Connected";
    public string ConnectionStatusColor { get; set; } = "#10B981";
    public bool IsScanning { get; set; } = false;
    
    // Sidebar Properties
    public bool HasNewAlerts { get; set; } = true;
    public bool IsCurrentlyScanning { get; set; } = false;
    
    // Commands
    public ReactiveCommand<Unit, Unit> NavigateToDashboardCommand { get; }
    public ReactiveCommand<Unit, Unit> NavigateToScannerCommand { get; }
    public ReactiveCommand<Unit, Unit> NavigateToReportsCommand { get; }
    public ReactiveCommand<Unit, Unit> NavigateToSettingsCommand { get; }
    public ReactiveCommand<Unit, Unit> ShowHelpCommand { get; }
    public ReactiveCommand<Unit, Unit> StartQuickScanCommand { get; }
    public ReactiveCommand<Unit, Unit> ViewAnalyticsCommand { get; }
    
    public MainWindowViewModel(ISecurityScanner? securityScanner = null, IScanResultRepository? scanResultRepository = null)
    {
        _securityScanner = securityScanner;
        _scanResultRepository = scanResultRepository;
        _currentView = new DashboardViewModel(scanResultRepository);
        IsDashboardSelected = true; // Start with dashboard selected
        
        NavigateToDashboardCommand = ReactiveCommand.Create(NavigateToDashboard);
        NavigateToScannerCommand = ReactiveCommand.Create(NavigateToScanner);
        NavigateToReportsCommand = ReactiveCommand.Create(NavigateToReports);
        NavigateToSettingsCommand = ReactiveCommand.Create(NavigateToSettings);
        ShowHelpCommand = ReactiveCommand.Create(ShowHelp);
        StartQuickScanCommand = ReactiveCommand.Create(StartQuickScan);
        ViewAnalyticsCommand = ReactiveCommand.Create(ViewAnalytics);
        
        // Update time every second
        var timer = new System.Timers.Timer(1000);
        timer.Elapsed += (_, _) => CurrentTime = DateTime.Now.ToString("HH:mm:ss");
        timer.Start();
    }
    
    private void NavigateToDashboard()
    {
        CurrentView = new DashboardViewModel(_scanResultRepository);
        this.RaisePropertyChanged(nameof(CurrentPage));
        IsDashboardSelected = true;
        IsScannerSelected = IsReportsSelected = IsSettingsSelected = false;
        this.RaisePropertyChanged(nameof(IsDashboardSelected));
        this.RaisePropertyChanged(nameof(IsScannerSelected));
        this.RaisePropertyChanged(nameof(IsReportsSelected));
        this.RaisePropertyChanged(nameof(IsSettingsSelected));
    }
    
    private void NavigateToScanner()
    {
        CurrentView = new ScannerViewModel(_securityScanner);
        this.RaisePropertyChanged(nameof(CurrentPage));
        IsScannerSelected = true;
        IsDashboardSelected = IsReportsSelected = IsSettingsSelected = false;
        this.RaisePropertyChanged(nameof(IsDashboardSelected));
        this.RaisePropertyChanged(nameof(IsScannerSelected));
        this.RaisePropertyChanged(nameof(IsReportsSelected));
        this.RaisePropertyChanged(nameof(IsSettingsSelected));
    }
    
    private void NavigateToReports()
    {
        CurrentView = new ReportsViewModel();
        this.RaisePropertyChanged(nameof(CurrentPage));
        IsReportsSelected = true;
        IsDashboardSelected = IsScannerSelected = IsSettingsSelected = false;
        this.RaisePropertyChanged(nameof(IsDashboardSelected));
        this.RaisePropertyChanged(nameof(IsScannerSelected));
        this.RaisePropertyChanged(nameof(IsReportsSelected));
        this.RaisePropertyChanged(nameof(IsSettingsSelected));
    }
    
    private void NavigateToSettings()
    {
        CurrentView = new SettingsViewModel();
        this.RaisePropertyChanged(nameof(CurrentPage));
        IsSettingsSelected = true;
        IsDashboardSelected = IsScannerSelected = IsReportsSelected = false;
        this.RaisePropertyChanged(nameof(IsDashboardSelected));
        this.RaisePropertyChanged(nameof(IsScannerSelected));
        this.RaisePropertyChanged(nameof(IsReportsSelected));
        this.RaisePropertyChanged(nameof(IsSettingsSelected));
    }
    
    private void ShowHelp()
    {
        // Open help dialog or browser
    }
    
    private void StartQuickScan()
    {
        // Start a quick security scan
        StatusText = "Starting quick scan...";
        IsScanning = true;
        IsCurrentlyScanning = true;
        this.RaisePropertyChanged(nameof(StatusText));
        this.RaisePropertyChanged(nameof(IsScanning));
        this.RaisePropertyChanged(nameof(IsCurrentlyScanning));
        
        // Navigate to scanner view
        NavigateToScanner();
        
        // If we have a real scanner, trigger it, otherwise simulate
        if (_securityScanner != null && !string.IsNullOrEmpty("localhost"))
        {
            // Could start real scan here if needed
        }
        else
        {
            // Simulate scan completion after 3 seconds
            var timer = new System.Timers.Timer(3000);
            timer.Elapsed += (_, _) => 
            {
                StatusText = "Quick scan completed";
                IsScanning = false;
                IsCurrentlyScanning = false;
                this.RaisePropertyChanged(nameof(StatusText));
                this.RaisePropertyChanged(nameof(IsScanning));
                this.RaisePropertyChanged(nameof(IsCurrentlyScanning));
                timer.Stop();
            };
            timer.Start();
        }
    }
    
    private void ViewAnalytics()
    {
        // Navigate to reports/analytics view
        NavigateToReports();
        StatusText = "Viewing security analytics";
        this.RaisePropertyChanged(nameof(StatusText));
    }
}