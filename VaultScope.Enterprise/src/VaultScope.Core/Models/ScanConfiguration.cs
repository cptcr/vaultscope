namespace VaultScope.Core.Models;

public class ScanConfiguration
{
    public string TargetUrl { get; set; } = string.Empty;
    
    public List<string> IncludedPaths { get; set; } = new() { "/" };
    
    public List<string> ExcludedPaths { get; set; } = new();
    
    public List<VulnerabilityType> VulnerabilityTypes { get; set; } = Enum.GetValues<VulnerabilityType>().ToList();
    
    public AuthenticationResult? Authentication { get; set; }
    
    public int MaxRequestsPerSecond { get; set; } = 10;
    
    public int RequestTimeout { get; set; } = 30000;
    
    public int MaxConcurrentRequests { get; set; } = 5;
    
    public bool FollowRedirects { get; set; } = true;
    
    public int MaxRedirects { get; set; } = 5;
    
    public bool TestAllHttpMethods { get; set; } = true;
    
    public List<string> CustomHeaders { get; set; } = new();
    
    public ScanDepth Depth { get; set; } = ScanDepth.Normal;
    
    public bool GenerateReport { get; set; } = true;
    
    public List<ReportFormat> ReportFormats { get; set; } = new() { ReportFormat.Html, ReportFormat.Json };
}

public enum VulnerabilityType
{
    SqlInjection,
    CrossSiteScripting,
    XmlExternalEntity,
    CommandInjection,
    PathTraversal,
    AuthenticationBypass,
    BrokenAccessControl,
    SecurityMisconfiguration,
    SensitiveDataExposure,
    MissingSecurityHeaders,
    InsecureDeserialization,
    ServerSideRequestForgery,
    RateLimiting
}

public enum ScanDepth
{
    Quick,
    Normal,
    Deep,
    Comprehensive
}

public enum ReportFormat
{
    Html,
    Pdf,
    Json,
    Xml,
    Csv
}