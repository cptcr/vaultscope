using VaultScope.Core.Models;

namespace VaultScope.Infrastructure.Data.Entities;

public class ScanResultEntity : BaseEntity
{
    public string TargetUrl { get; set; } = string.Empty;
    public DateTime StartTime { get; set; }
    public DateTime? EndTime { get; set; }
    public string Status { get; set; } = string.Empty;
    public int TotalRequestsMade { get; set; }
    public string? ErrorMessage { get; set; }
    
    // Foreign key to configuration
    public Guid? ConfigurationId { get; set; }
    public ScanConfigurationEntity? Configuration { get; set; }
    
    // Navigation properties
    public List<VulnerabilityEntity> Vulnerabilities { get; set; } = new();
    public SecurityScoreEntity? SecurityScore { get; set; }
    public List<EndpointEntity> Endpoints { get; set; } = new();
    public List<ReportEntity> Reports { get; set; } = new();
    
    // Computed properties
    public TimeSpan Duration => EndTime.HasValue ? EndTime.Value - StartTime : TimeSpan.Zero;
    
    public static ScanResultEntity FromDomainModel(ScanResult model)
    {
        return new ScanResultEntity
        {
            Id = model.Id,
            TargetUrl = model.TargetUrl,
            StartTime = model.StartTime,
            EndTime = model.EndTime,
            Status = model.Status.ToString(),
            TotalRequestsMade = model.TotalRequestsMade,
            ErrorMessage = model.ErrorMessage
        };
    }
    
    public ScanResult ToDomainModel()
    {
        var result = new ScanResult
        {
            Id = Id,
            TargetUrl = TargetUrl,
            StartTime = StartTime,
            EndTime = EndTime,
            Status = Enum.Parse<ScanStatus>(Status),
            TotalRequestsMade = TotalRequestsMade,
            ErrorMessage = ErrorMessage,
            Vulnerabilities = Vulnerabilities.Select(v => v.ToDomainModel()).ToList(),
            TestedEndpoints = Endpoints.Select(e => e.Url).ToList()
        };
        
        if (SecurityScore != null)
        {
            result.SecurityScore = SecurityScore.ToDomainModel();
        }
        
        // Calculate vulnerability count by severity
        result.VulnerabilityCountBySeverity = result.Vulnerabilities
            .GroupBy(v => v.Severity)
            .ToDictionary(g => g.Key.ToString(), g => g.Count());
        
        return result;
    }
}