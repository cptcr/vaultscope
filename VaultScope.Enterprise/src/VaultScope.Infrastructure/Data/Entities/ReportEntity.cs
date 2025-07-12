namespace VaultScope.Infrastructure.Data.Entities;

public class ReportEntity : BaseEntity
{
    public string FileName { get; set; } = string.Empty;
    public string Format { get; set; } = string.Empty;
    public string? FilePath { get; set; }
    public long FileSizeBytes { get; set; }
    public DateTime GeneratedAt { get; set; }
    public string? GeneratedBy { get; set; }
    
    // Report options used
    public bool IncludedExecutiveSummary { get; set; }
    public bool IncludedDetailedFindings { get; set; }
    public bool IncludedRemediation { get; set; }
    public bool IncludedSecurityScore { get; set; }
    public bool IncludedCharts { get; set; }
    public bool IncludedTimeline { get; set; }
    
    // Foreign key
    public Guid ScanResultId { get; set; }
    public ScanResultEntity ScanResult { get; set; } = null!;
}