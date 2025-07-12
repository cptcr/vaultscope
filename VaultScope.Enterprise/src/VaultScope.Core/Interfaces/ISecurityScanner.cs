using VaultScope.Core.Models;

namespace VaultScope.Core.Interfaces;

public interface ISecurityScanner
{
    Task<ScanResult> ScanAsync(ScanConfiguration configuration, CancellationToken cancellationToken = default);
    
    Task<ScanResult> QuickScanAsync(string targetUrl, CancellationToken cancellationToken = default);
    
    event EventHandler<ScanProgressEventArgs>? ProgressChanged;
    
    event EventHandler<VulnerabilityDetectedEventArgs>? VulnerabilityDetected;
}

public class ScanProgressEventArgs : EventArgs
{
    public double ProgressPercentage { get; set; }
    
    public string CurrentTask { get; set; } = string.Empty;
    
    public int VulnerabilitiesFound { get; set; }
    
    public int EndpointsTested { get; set; }
    
    public TimeSpan ElapsedTime { get; set; }
}

public class VulnerabilityDetectedEventArgs : EventArgs
{
    public Vulnerability Vulnerability { get; set; } = null!;
    
    public string Endpoint { get; set; } = string.Empty;
    
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
}