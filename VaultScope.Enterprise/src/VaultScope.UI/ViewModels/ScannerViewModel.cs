using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Reactive;
using System.Reactive.Linq;
using System.Threading;
using System.Threading.Tasks;
using ReactiveUI;
using VaultScope.Core.Models;
using VaultScope.Core.Services;
using VaultScope.Infrastructure.Data.Repositories;
using VaultScope.UI.Services;

namespace VaultScope.UI.ViewModels;

public class ScannerViewModel : ViewModelBase
{
    private readonly ISecurityScanner _scanner;
    private readonly IScanResultRepository _scanResultRepository;
    private readonly INotificationService _notificationService;
    private readonly INavigationService _navigationService;
    
    private string _targetUrl = string.Empty;
    private string _authenticationToken = string.Empty;
    private AuthenticationType _authenticationType = AuthenticationType.None;
    private bool _includeAuthentication;
    private bool _testAllHttpMethods = true;
    private bool _testCommonEndpoints = true;
    private bool _generateDetailedReport = true;
    private bool _isScanning;
    private double _scanProgress;
    private string _currentOperation = string.Empty;
    private ObservableCollection<string> _scanLog = new();
    private CancellationTokenSource? _cancellationTokenSource;
    private ScanResult? _currentScanResult;
    
    // Vulnerability detectors toggles
    private bool _enableSqlInjection = true;
    private bool _enableXss = true;
    private bool _enableCommandInjection = true;
    private bool _enableXxe = true;
    private bool _enableSsrf = true;
    private bool _enablePathTraversal = true;
    private bool _enableAuthBypass = true;
    private bool _enableSecurityHeaders = true;
    
    public ScannerViewModel()
    {
        // Design-time constructor
        _scanner = null!;
        _scanResultRepository = null!;
        _notificationService = null!;
        _navigationService = null!;
        LoadDesignTimeData();
    }
    
    public ScannerViewModel(
        ISecurityScanner scanner,
        IScanResultRepository scanResultRepository,
        INotificationService notificationService,
        INavigationService navigationService)
    {
        _scanner = scanner;
        _scanResultRepository = scanResultRepository;
        _notificationService = notificationService;
        _navigationService = navigationService;
        
        // Initialize commands
        StartScanCommand = ReactiveCommand.CreateFromTask(
            StartScanAsync,
            this.WhenAnyValue(x => x.IsScanning, x => x.TargetUrl,
                (isScanning, url) => !isScanning && !string.IsNullOrWhiteSpace(url)));
        
        StopScanCommand = ReactiveCommand.Create(
            StopScan,
            this.WhenAnyValue(x => x.IsScanning));
        
        ClearLogCommand = ReactiveCommand.Create(ClearLog);
        
        ViewLastResultCommand = ReactiveCommand.Create(
            ViewLastResult,
            this.WhenAnyValue(x => x.CurrentScanResult, result => result != null));
        
        // Subscribe to scanner progress
        _scanner.ProgressChanged += OnScannerProgressChanged;
        _scanner.StatusChanged += OnScannerStatusChanged;
        
        // Validation
        this.WhenAnyValue(x => x.TargetUrl)
            .Throttle(TimeSpan.FromMilliseconds(500))
            .Subscribe(ValidateUrl);
    }
    
    #region Properties
    
    public string TargetUrl
    {
        get => _targetUrl;
        set => this.RaiseAndSetIfChanged(ref _targetUrl, value);
    }
    
    public string AuthenticationToken
    {
        get => _authenticationToken;
        set => this.RaiseAndSetIfChanged(ref _authenticationToken, value);
    }
    
    public AuthenticationType AuthenticationType
    {
        get => _authenticationType;
        set => this.RaiseAndSetIfChanged(ref _authenticationType, value);
    }
    
    public bool IncludeAuthentication
    {
        get => _includeAuthentication;
        set => this.RaiseAndSetIfChanged(ref _includeAuthentication, value);
    }
    
    public bool TestAllHttpMethods
    {
        get => _testAllHttpMethods;
        set => this.RaiseAndSetIfChanged(ref _testAllHttpMethods, value);
    }
    
    public bool TestCommonEndpoints
    {
        get => _testCommonEndpoints;
        set => this.RaiseAndSetIfChanged(ref _testCommonEndpoints, value);
    }
    
    public bool GenerateDetailedReport
    {
        get => _generateDetailedReport;
        set => this.RaiseAndSetIfChanged(ref _generateDetailedReport, value);
    }
    
    public bool IsScanning
    {
        get => _isScanning;
        set => this.RaiseAndSetIfChanged(ref _isScanning, value);
    }
    
    public double ScanProgress
    {
        get => _scanProgress;
        set => this.RaiseAndSetIfChanged(ref _scanProgress, value);
    }
    
    public string CurrentOperation
    {
        get => _currentOperation;
        set => this.RaiseAndSetIfChanged(ref _currentOperation, value);
    }
    
    public ObservableCollection<string> ScanLog
    {
        get => _scanLog;
        set => this.RaiseAndSetIfChanged(ref _scanLog, value);
    }
    
    public ScanResult? CurrentScanResult
    {
        get => _currentScanResult;
        set => this.RaiseAndSetIfChanged(ref _currentScanResult, value);
    }
    
    // Detector toggles
    public bool EnableSqlInjection
    {
        get => _enableSqlInjection;
        set => this.RaiseAndSetIfChanged(ref _enableSqlInjection, value);
    }
    
    public bool EnableXss
    {
        get => _enableXss;
        set => this.RaiseAndSetIfChanged(ref _enableXss, value);
    }
    
    public bool EnableCommandInjection
    {
        get => _enableCommandInjection;
        set => this.RaiseAndSetIfChanged(ref _enableCommandInjection, value);
    }
    
    public bool EnableXxe
    {
        get => _enableXxe;
        set => this.RaiseAndSetIfChanged(ref _enableXxe, value);
    }
    
    public bool EnableSsrf
    {
        get => _enableSsrf;
        set => this.RaiseAndSetIfChanged(ref _enableSsrf, value);
    }
    
    public bool EnablePathTraversal
    {
        get => _enablePathTraversal;
        set => this.RaiseAndSetIfChanged(ref _enablePathTraversal, value);
    }
    
    public bool EnableAuthBypass
    {
        get => _enableAuthBypass;
        set => this.RaiseAndSetIfChanged(ref _enableAuthBypass, value);
    }
    
    public bool EnableSecurityHeaders
    {
        get => _enableSecurityHeaders;
        set => this.RaiseAndSetIfChanged(ref _enableSecurityHeaders, value);
    }
    
    #endregion
    
    #region Commands
    
    public ReactiveCommand<Unit, Unit> StartScanCommand { get; }
    public ReactiveCommand<Unit, Unit> StopScanCommand { get; }
    public ReactiveCommand<Unit, Unit> ClearLogCommand { get; }
    public ReactiveCommand<Unit, Unit> ViewLastResultCommand { get; }
    
    #endregion
    
    #region Methods
    
    private async Task StartScanAsync()
    {
        try
        {
            IsScanning = true;
            ScanProgress = 0;
            CurrentOperation = "Initializing scan...";
            ScanLog.Clear();
            
            AddLogEntry($"Starting security scan for {TargetUrl}");
            
            // Validate URL is localhost
            if (!IsLocalhostUrl(TargetUrl))
            {
                throw new InvalidOperationException("Only localhost URLs are allowed for security scanning");
            }
            
            // Create scan configuration
            var config = new ScanConfiguration
            {
                TargetUrl = TargetUrl,
                Authentication = IncludeAuthentication ? new AuthenticationConfig
                {
                    Type = AuthenticationType,
                    Token = AuthenticationToken
                } : null,
                TestAllHttpMethods = TestAllHttpMethods,
                TestCommonEndpoints = TestCommonEndpoints,
                GenerateDetailedReport = GenerateDetailedReport,
                EnabledDetectors = GetEnabledDetectors()
            };
            
            AddLogEntry($"Scan configuration: {config.EnabledDetectors.Count} detectors enabled");
            
            // Create cancellation token
            _cancellationTokenSource = new CancellationTokenSource();
            
            // Perform scan
            CurrentScanResult = await _scanner.PerformScanAsync(config, _cancellationTokenSource.Token);
            
            // Save to database
            AddLogEntry("Saving scan results to database...");
            await _scanResultRepository.AddAsync(CurrentScanResult);
            
            // Show summary
            var vulnerabilityCount = CurrentScanResult.Vulnerabilities.Count;
            var securityScore = CurrentScanResult.SecurityScore?.OverallScore ?? 0;
            
            AddLogEntry($"Scan completed! Found {vulnerabilityCount} vulnerabilities. Security score: {securityScore:F1}/100");
            
            // Show notification
            _notificationService.Show(
                "Scan Complete",
                $"Found {vulnerabilityCount} vulnerabilities. Security score: {securityScore:F1}/100",
                vulnerabilityCount > 0 ? NotificationType.Warning : NotificationType.Success);
            
            // Offer to view results
            var viewResults = await _notificationService.ShowConfirmationAsync(
                "View Results?",
                "Would you like to view the detailed scan results?");
            
            if (viewResults)
            {
                ViewLastResult();
            }
        }
        catch (OperationCanceledException)
        {
            AddLogEntry("Scan cancelled by user");
            _notificationService.Show("Scan Cancelled", "The security scan was cancelled", NotificationType.Information);
        }
        catch (Exception ex)
        {
            AddLogEntry($"Error: {ex.Message}");
            _notificationService.Show("Scan Error", ex.Message, NotificationType.Error);
        }
        finally
        {
            IsScanning = false;
            ScanProgress = 0;
            CurrentOperation = string.Empty;
            _cancellationTokenSource?.Dispose();
            _cancellationTokenSource = null;
        }
    }
    
    private void StopScan()
    {
        _cancellationTokenSource?.Cancel();
        AddLogEntry("Requesting scan cancellation...");
    }
    
    private void ClearLog()
    {
        ScanLog.Clear();
    }
    
    private void ViewLastResult()
    {
        if (CurrentScanResult != null)
        {
            _navigationService.NavigateTo<ScanResultDetailViewModel>(CurrentScanResult.Id);
        }
    }
    
    private void ValidateUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return;
        
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            AddLogEntry("Invalid URL format");
            return;
        }
        
        if (!IsLocalhostUrl(url))
        {
            AddLogEntry("Warning: Only localhost URLs are allowed for security scanning");
        }
    }
    
    private bool IsLocalhostUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return false;
        
        return uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
               uri.Host.Equals("127.0.0.1") ||
               uri.Host.Equals("[::1]") ||
               uri.Host.StartsWith("localhost:", StringComparison.OrdinalIgnoreCase);
    }
    
    private List<string> GetEnabledDetectors()
    {
        var detectors = new List<string>();
        
        if (EnableSqlInjection) detectors.Add("SqlInjection");
        if (EnableXss) detectors.Add("CrossSiteScripting");
        if (EnableCommandInjection) detectors.Add("CommandInjection");
        if (EnableXxe) detectors.Add("XmlExternalEntity");
        if (EnableSsrf) detectors.Add("ServerSideRequestForgery");
        if (EnablePathTraversal) detectors.Add("PathTraversal");
        if (EnableAuthBypass) detectors.Add("AuthenticationBypass");
        if (EnableSecurityHeaders) detectors.Add("SecurityHeaders");
        
        return detectors;
    }
    
    private void AddLogEntry(string message)
    {
        var timestamp = DateTime.Now.ToString("HH:mm:ss");
        ScanLog.Add($"[{timestamp}] {message}");
    }
    
    private void OnScannerProgressChanged(object? sender, ScanProgressEventArgs e)
    {
        ScanProgress = e.ProgressPercentage;
        CurrentOperation = e.CurrentOperation;
        
        if (!string.IsNullOrEmpty(e.Message))
        {
            AddLogEntry(e.Message);
        }
    }
    
    private void OnScannerStatusChanged(object? sender, string status)
    {
        AddLogEntry(status);
    }
    
    private void LoadDesignTimeData()
    {
        TargetUrl = "http://localhost:3000/api";
        ScanLog = new ObservableCollection<string>
        {
            "[10:23:45] Starting security scan for http://localhost:3000/api",
            "[10:23:45] Scan configuration: 8 detectors enabled",
            "[10:23:46] Testing endpoint: /api/users",
            "[10:23:47] Found SQL Injection vulnerability in /api/users",
            "[10:23:48] Testing endpoint: /api/auth",
            "[10:23:49] Scan progress: 50%"
        };
        ScanProgress = 50;
        CurrentOperation = "Testing authentication endpoints...";
    }
    
    #endregion
}

public class ScanProgressEventArgs : EventArgs
{
    public double ProgressPercentage { get; set; }
    public string CurrentOperation { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
}