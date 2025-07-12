namespace VaultScope.Infrastructure.Data.Entities;

public class EndpointEntity : BaseEntity
{
    public string Url { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public int VulnerabilityCount { get; set; }
    
    // Foreign key
    public Guid ScanResultId { get; set; }
    public ScanResultEntity ScanResult { get; set; } = null!;
}