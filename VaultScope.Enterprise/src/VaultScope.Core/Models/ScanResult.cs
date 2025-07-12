namespace VaultScope.Core.Models;

public class ScanResult
{
    public Guid Id { get; set; } = Guid.NewGuid();
    
    public string TargetUrl { get; set; } = string.Empty;
    
    public DateTime StartTime { get; set; }
    
    public DateTime? EndTime { get; set; }
    
    public ScanStatus Status { get; set; } = ScanStatus.Pending;
    
    public List<Vulnerability> Vulnerabilities { get; set; } = new();
    
    public SecurityScore SecurityScore { get; set; } = new();
    
    public Dictionary<string, int> VulnerabilityCountBySeverity { get; set; } = new();
    
    public List<string> TestedEndpoints { get; set; } = new();
    
    public int TotalRequestsMade { get; set; }
    
    public TimeSpan Duration => EndTime.HasValue ? EndTime.Value - StartTime : TimeSpan.Zero;
    
    public string? ErrorMessage { get; set; }
    
    public Dictionary<string, object> Metadata { get; set; } = new();
}

public enum ScanStatus
{
    Pending,
    InProgress,
    Completed,
    Failed,
    Cancelled
}