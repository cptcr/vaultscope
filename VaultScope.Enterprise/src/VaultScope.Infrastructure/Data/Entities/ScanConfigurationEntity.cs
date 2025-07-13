using VaultScope.Core.Models;
using VaultScope.Infrastructure.Json;

namespace VaultScope.Infrastructure.Data.Entities;

public class ScanConfigurationEntity : BaseEntity
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string TargetUrl { get; set; } = string.Empty;
    
    // Stored as semicolon-separated strings
    public List<string> IncludedPaths { get; set; } = new();
    public List<string> ExcludedPaths { get; set; } = new();
    public List<string> VulnerabilityTypes { get; set; } = new();
    
    public int MaxRequestsPerSecond { get; set; } = 10;
    public int RequestTimeout { get; set; } = 30000;
    public int MaxConcurrentRequests { get; set; } = 5;
    public bool FollowRedirects { get; set; } = true;
    public int MaxRedirects { get; set; } = 5;
    public bool TestAllHttpMethods { get; set; } = true;
    
    // Stored as JSON
    public Dictionary<string, string> CustomHeaders { get; set; } = new();
    
    public string Depth { get; set; } = "Normal";
    public bool GenerateReport { get; set; } = true;
    public string ReportFormats { get; set; } = "Html;Json";
    
    // Authentication settings (simplified - in real app, encrypt sensitive data)
    public string? AuthType { get; set; }
    public string? AuthToken { get; set; }
    public string? AuthHeaders { get; set; }
    
    public bool IsActive { get; set; } = true;
    
    public static ScanConfigurationEntity FromDomainModel(ScanConfiguration model, string name)
    {
        return new ScanConfigurationEntity
        {
            Name = name,
            TargetUrl = model.TargetUrl,
            IncludedPaths = model.IncludedPaths,
            ExcludedPaths = model.ExcludedPaths,
            VulnerabilityTypes = model.VulnerabilityTypes.Select(v => v.ToString()).ToList(),
            MaxRequestsPerSecond = model.MaxRequestsPerSecond,
            RequestTimeout = model.RequestTimeout,
            MaxConcurrentRequests = model.MaxConcurrentRequests,
            FollowRedirects = model.FollowRedirects,
            MaxRedirects = model.MaxRedirects,
            TestAllHttpMethods = model.TestAllHttpMethods,
            CustomHeaders = model.CustomHeaders.ToDictionary(h => h, h => h),
            Depth = model.Depth.ToString(),
            GenerateReport = model.GenerateReport,
            ReportFormats = string.Join(";", model.ReportFormats.Select(f => f.ToString())),
            AuthType = model.Authentication?.Type.ToString(),
            AuthToken = model.Authentication?.Token,
            AuthHeaders = model.Authentication != null ? System.Text.Json.JsonSerializer.Serialize(model.Authentication.Headers) : null
        };
    }
    
    public ScanConfiguration ToDomainModel()
    {
        var config = new ScanConfiguration
        {
            TargetUrl = TargetUrl,
            IncludedPaths = IncludedPaths,
            ExcludedPaths = ExcludedPaths,
            VulnerabilityTypes = VulnerabilityTypes.Select(v => Enum.Parse<VulnerabilityType>(v)).ToList(),
            MaxRequestsPerSecond = MaxRequestsPerSecond,
            RequestTimeout = RequestTimeout,
            MaxConcurrentRequests = MaxConcurrentRequests,
            FollowRedirects = FollowRedirects,
            MaxRedirects = MaxRedirects,
            TestAllHttpMethods = TestAllHttpMethods,
            CustomHeaders = CustomHeaders.Keys.ToList(),
            Depth = Enum.Parse<ScanDepth>(Depth),
            GenerateReport = GenerateReport,
            ReportFormats = ReportFormats.Split(';', StringSplitOptions.RemoveEmptyEntries)
                .Select(f => Enum.Parse<ReportFormat>(f)).ToList()
        };
        
        if (!string.IsNullOrEmpty(AuthType))
        {
            config.Authentication = new AuthenticationResult
            {
                IsAuthenticated = true,
                Type = Enum.Parse<AuthenticationType>(AuthType),
                Token = AuthToken,
                Headers = !string.IsNullOrEmpty(AuthHeaders) 
                    ? System.Text.Json.JsonSerializer.Deserialize(AuthHeaders, VaultScopeJsonContext.Default.DictionaryStringString) ?? new()
                    : new()
            };
        }
        
        return config;
    }
}