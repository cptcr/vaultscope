using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Reactive;
using System.Threading;
using System.Threading.Tasks;
using ReactiveUI;
using VaultScope.Core.Constants;
using VaultScope.Core.Interfaces;
using VaultScope.Core.Models;

namespace VaultScope.UI.ViewModels;

public class ScannerViewModel : ViewModelBase
{
    private readonly ISecurityScanner? _securityScanner;
    private CancellationTokenSource? _cancellationTokenSource;
    private string _targetUrl = "";
    private bool _isScanning;
    private string _statusMessage = "Ready to scan";
    private int _progress;
    private ScanResult? _lastScanResult;
    
    public string TargetUrl
    {
        get => _targetUrl;
        set => this.RaiseAndSetIfChanged(ref _targetUrl, value);
    }
    
    public bool IsScanning
    {
        get => _isScanning;
        set => this.RaiseAndSetIfChanged(ref _isScanning, value);
    }

    
    public string StatusMessage
    {
        get => _statusMessage;
        set => this.RaiseAndSetIfChanged(ref _statusMessage, value);
    }
    
    public int Progress
    {
        get => _progress;
        set => this.RaiseAndSetIfChanged(ref _progress, value);
    }
    
    public ObservableCollection<string> ScanLog { get; } = new();
    public ObservableCollection<Vulnerability> DetectedVulnerabilities { get; } = new();
    
    // Commands
    public ReactiveCommand<Unit, Unit> StartScanCommand { get; }
    public ReactiveCommand<Unit, Unit> StopScanCommand { get; }
    public ReactiveCommand<Unit, Unit> ClearLogCommand { get; }
    public ReactiveCommand<Unit, Unit> ViewLastResultCommand { get; }
    
    public ScannerViewModel(ISecurityScanner? securityScanner = null)
    {
        _securityScanner = securityScanner;
        
        StartScanCommand = ReactiveCommand.Create(StartScan);
        StopScanCommand = ReactiveCommand.Create(StopScan);
        ClearLogCommand = ReactiveCommand.Create(ClearLog);
        ViewLastResultCommand = ReactiveCommand.Create(ViewLastResult);
    }
    
    private async void StartScan()
    {
        if (string.IsNullOrWhiteSpace(TargetUrl))
        {
            StatusMessage = "Please enter a valid URL";
            return;
        }
        
        if (_securityScanner == null)
        {
            StatusMessage = "Security scanner not available. Use 'Load Example Data' button to simulate.";
            return;
        }
        
        IsScanning = true;
        StatusMessage = "Starting scan...";
        Progress = 0;
        DetectedVulnerabilities.Clear();
        _cancellationTokenSource = new CancellationTokenSource();
        
        ScanLog.Add($"[{DateTime.Now:HH:mm:ss}] Starting security scan of {TargetUrl}");
        
        try
        {
            // Subscribe to events
            _securityScanner.ProgressChanged += OnScanProgressChanged;
            _securityScanner.VulnerabilityDetected += OnVulnerabilityDetected;
            
            // Start real security scan
            _lastScanResult = await _securityScanner.ScanAsync(new ScanConfiguration
            {
                TargetUrl = TargetUrl,
                Depth = ScanDepth.Normal,
                VulnerabilityTypes = new List<VulnerabilityType>
                {
                    VulnerabilityType.SqlInjection,
                    VulnerabilityType.CrossSiteScripting,
                    VulnerabilityType.CommandInjection,
                    VulnerabilityType.AuthenticationBypass,
                    VulnerabilityType.MissingSecurityHeaders,
                    VulnerabilityType.PathTraversal,
                    VulnerabilityType.ServerSideRequestForgery,
                    VulnerabilityType.InsecureDeserialization
                },
                MaxConcurrentRequests = 5,
                MaxRequestsPerSecond = 10,
                IncludedPaths = new List<string> { "/" },
                ExcludedPaths = new List<string>(),
                TestAllHttpMethods = true
            }, _cancellationTokenSource.Token);
            
            IsScanning = false;
            Progress = 100;
            StatusMessage = $"Scan completed. Found {_lastScanResult.Vulnerabilities.Count} vulnerabilities";
            ScanLog.Add($"[{DateTime.Now:HH:mm:ss}] Scan completed successfully");
            ScanLog.Add($"[{DateTime.Now:HH:mm:ss}] Security Score: {_lastScanResult.SecurityScore:F1}/10");
            
            foreach (var vuln in _lastScanResult.Vulnerabilities)
            {
                DetectedVulnerabilities.Add(vuln);
            }
        }
        catch (OperationCanceledException)
        {
            IsScanning = false;
            StatusMessage = "Scan cancelled";
            ScanLog.Add($"[{DateTime.Now:HH:mm:ss}] Scan cancelled by user");
        }
        catch (Exception ex)
        {
            IsScanning = false;
            StatusMessage = $"Scan failed: {ex.Message}";
            ScanLog.Add($"[{DateTime.Now:HH:mm:ss}] Scan failed: {ex.Message}");
        }
        finally
        {
            if (_securityScanner != null)
            {
                _securityScanner.ProgressChanged -= OnScanProgressChanged;
                _securityScanner.VulnerabilityDetected -= OnVulnerabilityDetected;
            }
        }
    }
    
    private void StopScan()
    {
        _cancellationTokenSource?.Cancel();
        IsScanning = false;
        StatusMessage = "Scan stopped";
        ScanLog.Add($"[{DateTime.Now:HH:mm:ss}] Scan stopped by user");
    }
    
    private void ClearLog()
    {
        ScanLog.Clear();
        DetectedVulnerabilities.Clear();
    }
    
    private void ViewLastResult()
    {
        if (_lastScanResult != null)
        {
            StatusMessage = $"Last scan: {_lastScanResult.Vulnerabilities.Count} vulnerabilities found";
        }
        else
        {
            StatusMessage = "No previous scan results available";
        }
    }
    
    
    private void OnScanProgressChanged(object? sender, ScanProgressEventArgs e)
    {
        Progress = (int)e.ProgressPercentage;
        StatusMessage = e.CurrentTask ?? "Scanning...";
        
        if (!string.IsNullOrEmpty(e.CurrentTask))
        {
            ScanLog.Add($"[{DateTime.Now:HH:mm:ss}] {e.CurrentTask}");
        }
    }
    
    private void OnVulnerabilityDetected(object? sender, VulnerabilityDetectedEventArgs e)
    {
        DetectedVulnerabilities.Add(e.Vulnerability);
        ScanLog.Add($"[{DateTime.Now:HH:mm:ss}] Found {e.Vulnerability.Severity} vulnerability: {e.Vulnerability.Title}");
    }
}