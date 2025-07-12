using System;
using System.Reactive;
using System.Reactive.Linq;
using System.Threading.Tasks;
using Avalonia.Media;
using ReactiveUI;
using VaultScope.UI.Services;

namespace VaultScope.UI.ViewModels;

public class MainWindowViewModel : ViewModelBase
{
    private readonly INavigationService _navigationService;
    private ViewModelBase _currentPage;
    private string _statusText = "Ready";
    private string _connectionStatus = "Connected";
    private IBrush _connectionStatusColor = Brushes.LimeGreen;
    private bool _isScanning;
    private string _currentTime;
    
    // Navigation states
    private bool _isDashboardSelected = true;
    private bool _isScannerSelected;
    private bool _isReportsSelected;
    private bool _isHistorySelected;
    private bool _isSettingsSelected;
    
    public MainWindowViewModel(INavigationService navigationService)
    {
        _navigationService = navigationService;
        _currentPage = new DashboardViewModel();
        
        // Setup navigation commands
        NavigateToDashboardCommand = ReactiveCommand.Create(NavigateToDashboard);
        NavigateToScannerCommand = ReactiveCommand.Create(NavigateToScanner);
        NavigateToReportsCommand = ReactiveCommand.Create(NavigateToReports);
        NavigateToHistoryCommand = ReactiveCommand.Create(NavigateToHistory);
        NavigateToSettingsCommand = ReactiveCommand.Create(NavigateToSettings);
        ShowHelpCommand = ReactiveCommand.CreateFromTask(ShowHelp);
        
        // Update time every second
        Observable.Timer(TimeSpan.Zero, TimeSpan.FromSeconds(1))
            .ObserveOn(RxApp.MainThreadScheduler)
            .Subscribe(_ => CurrentTime = DateTime.Now.ToString("HH:mm:ss"));
        
        // Subscribe to navigation events
        _navigationService.CurrentPageChanged += OnCurrentPageChanged;
    }
    
    public ViewModelBase CurrentPage
    {
        get => _currentPage;
        set => this.RaiseAndSetIfChanged(ref _currentPage, value);
    }
    
    public string StatusText
    {
        get => _statusText;
        set => this.RaiseAndSetIfChanged(ref _statusText, value);
    }
    
    public string ConnectionStatus
    {
        get => _connectionStatus;
        set => this.RaiseAndSetIfChanged(ref _connectionStatus, value);
    }
    
    public IBrush ConnectionStatusColor
    {
        get => _connectionStatusColor;
        set => this.RaiseAndSetIfChanged(ref _connectionStatusColor, value);
    }
    
    public bool IsScanning
    {
        get => _isScanning;
        set => this.RaiseAndSetIfChanged(ref _isScanning, value);
    }
    
    public string CurrentTime
    {
        get => _currentTime;
        set => this.RaiseAndSetIfChanged(ref _currentTime, value);
    }
    
    // Navigation state properties
    public bool IsDashboardSelected
    {
        get => _isDashboardSelected;
        set => this.RaiseAndSetIfChanged(ref _isDashboardSelected, value);
    }
    
    public bool IsScannerSelected
    {
        get => _isScannerSelected;
        set => this.RaiseAndSetIfChanged(ref _isScannerSelected, value);
    }
    
    public bool IsReportsSelected
    {
        get => _isReportsSelected;
        set => this.RaiseAndSetIfChanged(ref _isReportsSelected, value);
    }
    
    public bool IsHistorySelected
    {
        get => _isHistorySelected;
        set => this.RaiseAndSetIfChanged(ref _isHistorySelected, value);
    }
    
    public bool IsSettingsSelected
    {
        get => _isSettingsSelected;
        set => this.RaiseAndSetIfChanged(ref _isSettingsSelected, value);
    }
    
    // Commands
    public ReactiveCommand<Unit, Unit> NavigateToDashboardCommand { get; }
    public ReactiveCommand<Unit, Unit> NavigateToScannerCommand { get; }
    public ReactiveCommand<Unit, Unit> NavigateToReportsCommand { get; }
    public ReactiveCommand<Unit, Unit> NavigateToHistoryCommand { get; }
    public ReactiveCommand<Unit, Unit> NavigateToSettingsCommand { get; }
    public ReactiveCommand<Unit, Unit> ShowHelpCommand { get; }
    
    private void NavigateToDashboard()
    {
        ResetNavigationStates();
        IsDashboardSelected = true;
        _navigationService.NavigateTo<DashboardViewModel>();
    }
    
    private void NavigateToScanner()
    {
        ResetNavigationStates();
        IsScannerSelected = true;
        _navigationService.NavigateTo<ScannerViewModel>();
    }
    
    private void NavigateToReports()
    {
        ResetNavigationStates();
        IsReportsSelected = true;
        _navigationService.NavigateTo<ReportsViewModel>();
    }
    
    private void NavigateToHistory()
    {
        ResetNavigationStates();
        IsHistorySelected = true;
        _navigationService.NavigateTo<ScanHistoryViewModel>();
    }
    
    private void NavigateToSettings()
    {
        ResetNavigationStates();
        IsSettingsSelected = true;
        _navigationService.NavigateTo<SettingsViewModel>();
    }
    
    private async Task ShowHelp()
    {
        // Open help documentation or show help dialog
        await Task.CompletedTask;
    }
    
    private void ResetNavigationStates()
    {
        IsDashboardSelected = false;
        IsScannerSelected = false;
        IsReportsSelected = false;
        IsHistorySelected = false;
        IsSettingsSelected = false;
    }
    
    private void OnCurrentPageChanged(object? sender, ViewModelBase viewModel)
    {
        CurrentPage = viewModel;
        StatusText = $"Navigated to {viewModel.GetType().Name.Replace("ViewModel", "")}";
    }
    
    public void UpdateScanningStatus(bool isScanning)
    {
        IsScanning = isScanning;
        StatusText = isScanning ? "Security scan in progress..." : "Ready";
    }
    
    public void UpdateConnectionStatus(bool isConnected, string message)
    {
        ConnectionStatus = message;
        ConnectionStatusColor = isConnected ? Brushes.LimeGreen : Brushes.OrangeRed;
    }
}