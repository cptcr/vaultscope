using VaultScope.Core.Models;

namespace VaultScope.Core.Interfaces;

public interface IReportGenerator
{
    ReportFormat Format { get; }
    
    Task<byte[]> GenerateAsync(ScanResult scanResult, ReportOptions options);
    
    Task SaveToFileAsync(ScanResult scanResult, string filePath, ReportOptions options);
}

public class ReportOptions
{
    public string Title { get; set; } = "VaultScope Security Assessment Report";
    
    public string CompanyName { get; set; } = string.Empty;
    
    public bool IncludeExecutiveSummary { get; set; } = true;
    
    public bool IncludeDetailedFindings { get; set; } = true;
    
    public bool IncludeRemediation { get; set; } = true;
    
    public bool IncludeSecurityScore { get; set; } = true;
    
    public bool IncludeCharts { get; set; } = true;
    
    public bool IncludeTimeline { get; set; } = true;
    
    public Dictionary<string, string> CustomFields { get; set; } = new();
}