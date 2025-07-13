using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using VaultScope.Core.Interfaces;
using VaultScope.Core.Models;
using VaultScope.Infrastructure.Json;

namespace VaultScope.Infrastructure.Reporting;

public class JsonReportGenerator : IReportGenerator
{
    private readonly JsonSerializerOptions _options;
    
    public ReportFormat Format => ReportFormat.Json;
    
    public JsonReportGenerator()
    {
        _options = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Converters =
            {
                new JsonStringEnumConverter(JsonNamingPolicy.CamelCase)
            }
        };
    }
    
    public Task<byte[]> GenerateAsync(ScanResult scanResult, ReportOptions options)
    {
        var report = CreateJsonReport(scanResult, options);
        var json = JsonSerializer.Serialize(report, VaultScopeJsonContext.Default.JsonReport);
        return Task.FromResult(Encoding.UTF8.GetBytes(json));
    }
    
    public async Task SaveToFileAsync(ScanResult scanResult, string filePath, ReportOptions options)
    {
        var report = CreateJsonReport(scanResult, options);
        var json = JsonSerializer.Serialize(report, VaultScopeJsonContext.Default.JsonReport);
        await File.WriteAllTextAsync(filePath, json);
    }
    
    private JsonReport CreateJsonReport(ScanResult scanResult, ReportOptions options)
    {
        var report = new JsonReport
        {
            Metadata = new ReportMetadata
            {
                Title = options.Title,
                GeneratedAt = DateTime.UtcNow,
                GeneratedBy = "VaultScope Enterprise",
                Version = "1.0.0",
                Company = options.CompanyName,
                CustomFields = options.CustomFields
            },
            
            ScanSummary = new ScanSummary
            {
                TargetUrl = scanResult.TargetUrl,
                StartTime = scanResult.StartTime,
                EndTime = scanResult.EndTime,
                Duration = scanResult.Duration.TotalSeconds,
                Status = scanResult.Status.ToString(),
                TotalRequestsMade = scanResult.TotalRequestsMade,
                EndpointsTested = scanResult.TestedEndpoints.Count,
                VulnerabilitiesFound = scanResult.Vulnerabilities.Count
            },
            
            RiskAssessment = new RiskAssessment
            {
                OverallRisk = DetermineRiskLevel(scanResult),
                VulnerabilityBreakdown = scanResult.VulnerabilityCountBySeverity,
                CriticalFindings = scanResult.Vulnerabilities.Count(v => v.Severity == VulnerabilitySeverity.Critical),
                RequiresImmediateAction = scanResult.Vulnerabilities.Any(v => v.Severity == VulnerabilitySeverity.Critical)
            }
        };
        
        if (options.IncludeSecurityScore && scanResult.SecurityScore != null)
        {
            report.SecurityScore = new SecurityScoreReport
            {
                OverallScore = scanResult.SecurityScore.OverallScore,
                Grade = scanResult.SecurityScore.Grade,
                CategoryScores = scanResult.SecurityScore.CategoryScores
                    .ToDictionary(c => c.Key, c => new CategoryScoreReport
                    {
                        Score = c.Value.Score,
                        TestsPassed = c.Value.TestsPassed,
                        TotalTests = c.Value.TotalTests,
                        FailedTests = c.Value.FailedTests
                    }),
                Strengths = scanResult.SecurityScore.Strengths,
                Weaknesses = scanResult.SecurityScore.Weaknesses,
                Recommendations = scanResult.SecurityScore.Recommendations
            };
        }
        
        if (options.IncludeDetailedFindings)
        {
            report.Vulnerabilities = scanResult.Vulnerabilities
                .Select(v => new VulnerabilityReport
                {
                    Id = v.Id,
                    Type = v.Type,
                    Severity = v.Severity.ToString(),
                    Title = v.Title,
                    Description = v.Description,
                    AffectedEndpoint = v.AffectedEndpoint,
                    HttpMethod = v.HttpMethod,
                    PayloadUsed = options.IncludeDetailedFindings ? v.PayloadUsed : null,
                    Evidence = options.IncludeDetailedFindings ? v.Evidence : null,
                    Remediation = options.IncludeRemediation ? v.Remediation : null,
                    CweId = v.CweId,
                    OwaspCategory = v.OwaspCategory,
                    ConfidenceScore = v.ConfidenceScore,
                    DiscoveredAt = v.DiscoveredAt,
                    Metadata = v.Metadata
                })
                .ToList();
        }
        
        if (options.IncludeExecutiveSummary)
        {
            report.ExecutiveSummary = GenerateExecutiveSummary(scanResult);
        }
        
        if (options.IncludeRemediation)
        {
            report.RemediationPlan = GenerateRemediationPlan(scanResult);
        }
        
        report.TestedEndpoints = scanResult.TestedEndpoints;
        
        return report;
    }
    
    private string GenerateExecutiveSummary(ScanResult scanResult)
    {
        var summary = new StringBuilder();
        
        summary.AppendLine($"Security assessment completed for {scanResult.TargetUrl}.");
        summary.AppendLine($"Scan duration: {scanResult.Duration.TotalMinutes:F1} minutes.");
        summary.AppendLine($"Total vulnerabilities found: {scanResult.Vulnerabilities.Count}");
        
        if (scanResult.Vulnerabilities.Any())
        {
            summary.AppendLine();
            summary.AppendLine("Severity breakdown:");
            foreach (var severity in Enum.GetValues<VulnerabilitySeverity>().OrderByDescending(s => s))
            {
                var count = scanResult.Vulnerabilities.Count(v => v.Severity == severity);
                if (count > 0)
                {
                    summary.AppendLine($"- {severity}: {count}");
                }
            }
        }
        
        var riskLevel = DetermineRiskLevel(scanResult);
        summary.AppendLine();
        summary.AppendLine($"Overall risk level: {riskLevel}");
        
        if (scanResult.Vulnerabilities.Any(v => v.Severity == VulnerabilitySeverity.Critical))
        {
            summary.AppendLine();
            summary.AppendLine("CRITICAL: Immediate action required to address critical vulnerabilities.");
        }
        
        return summary.ToString();
    }
    
    private RemediationPlan GenerateRemediationPlan(ScanResult scanResult)
    {
        var plan = new RemediationPlan
        {
            ImmediateActions = new List<string>(),
            ShortTermActions = new List<string>(),
            LongTermActions = new List<string>(),
            EstimatedEffort = EstimateEffort(scanResult)
        };
        
        // Immediate actions (Critical vulnerabilities)
        if (scanResult.Vulnerabilities.Any(v => v.Severity == VulnerabilitySeverity.Critical))
        {
            plan.ImmediateActions.Add("Address all critical vulnerabilities within 24-48 hours");
            
            var criticalTypes = scanResult.Vulnerabilities
                .Where(v => v.Severity == VulnerabilitySeverity.Critical)
                .Select(v => v.Type)
                .Distinct();
            
            foreach (var type in criticalTypes)
            {
                plan.ImmediateActions.Add($"Fix {type} vulnerabilities immediately");
            }
        }
        
        // Short-term actions (High vulnerabilities)
        if (scanResult.Vulnerabilities.Any(v => v.Severity == VulnerabilitySeverity.High))
        {
            plan.ShortTermActions.Add("Address high-severity vulnerabilities within 1 week");
            plan.ShortTermActions.Add("Implement input validation framework");
            plan.ShortTermActions.Add("Review and update authentication mechanisms");
        }
        
        // Long-term actions
        plan.LongTermActions.Add("Implement secure software development lifecycle (SSDLC)");
        plan.LongTermActions.Add("Conduct regular security assessments (quarterly)");
        plan.LongTermActions.Add("Provide security training to development team");
        plan.LongTermActions.Add("Implement automated security testing in CI/CD pipeline");
        plan.LongTermActions.Add("Establish security monitoring and alerting");
        
        // Recommendations by vulnerability type
        var typeGroups = scanResult.Vulnerabilities
            .GroupBy(v => v.Type)
            .OrderByDescending(g => g.Count());
        
        plan.RecommendationsByType = typeGroups
            .ToDictionary(
                g => g.Key,
                g => g.First().Remediation ?? "Implement security best practices"
            );
        
        return plan;
    }
    
    private string EstimateEffort(ScanResult scanResult)
    {
        var criticalCount = scanResult.Vulnerabilities.Count(v => v.Severity == VulnerabilitySeverity.Critical);
        var highCount = scanResult.Vulnerabilities.Count(v => v.Severity == VulnerabilitySeverity.High);
        var mediumCount = scanResult.Vulnerabilities.Count(v => v.Severity == VulnerabilitySeverity.Medium);
        
        var totalEffortHours = (criticalCount * 8) + (highCount * 4) + (mediumCount * 2);
        
        if (totalEffortHours <= 40)
            return "1 week";
        if (totalEffortHours <= 80)
            return "2 weeks";
        if (totalEffortHours <= 160)
            return "1 month";
        
        return "2+ months";
    }
    
    private string DetermineRiskLevel(ScanResult scanResult)
    {
        if (scanResult.Vulnerabilities.Any(v => v.Severity == VulnerabilitySeverity.Critical))
            return "CRITICAL";
        
        if (scanResult.Vulnerabilities.Count(v => v.Severity == VulnerabilitySeverity.High) >= 3)
            return "HIGH";
        
        if (scanResult.Vulnerabilities.Any(v => v.Severity == VulnerabilitySeverity.High))
            return "MEDIUM";
        
        if (scanResult.Vulnerabilities.Any())
            return "LOW";
        
        return "MINIMAL";
    }
}

// JSON Report Models
public class JsonReport
{
    public ReportMetadata Metadata { get; set; } = new();
    public ScanSummary ScanSummary { get; set; } = new();
    public RiskAssessment RiskAssessment { get; set; } = new();
    public SecurityScoreReport? SecurityScore { get; set; }
    public string? ExecutiveSummary { get; set; }
    public List<VulnerabilityReport>? Vulnerabilities { get; set; }
    public RemediationPlan? RemediationPlan { get; set; }
    public List<string> TestedEndpoints { get; set; } = new();
}

public class ReportMetadata
{
    public string Title { get; set; } = string.Empty;
    public DateTime GeneratedAt { get; set; }
    public string GeneratedBy { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string? Company { get; set; }
    public Dictionary<string, string> CustomFields { get; set; } = new();
}

public class ScanSummary
{
    public string TargetUrl { get; set; } = string.Empty;
    public DateTime StartTime { get; set; }
    public DateTime? EndTime { get; set; }
    public double Duration { get; set; }
    public string Status { get; set; } = string.Empty;
    public int TotalRequestsMade { get; set; }
    public int EndpointsTested { get; set; }
    public int VulnerabilitiesFound { get; set; }
}

public class RiskAssessment
{
    public string OverallRisk { get; set; } = string.Empty;
    public Dictionary<string, int> VulnerabilityBreakdown { get; set; } = new();
    public int CriticalFindings { get; set; }
    public bool RequiresImmediateAction { get; set; }
}

public class SecurityScoreReport
{
    public double OverallScore { get; set; }
    public string Grade { get; set; } = string.Empty;
    public Dictionary<string, CategoryScoreReport> CategoryScores { get; set; } = new();
    public List<string> Strengths { get; set; } = new();
    public List<string> Weaknesses { get; set; } = new();
    public List<string> Recommendations { get; set; } = new();
}

public class CategoryScoreReport
{
    public double Score { get; set; }
    public int TestsPassed { get; set; }
    public int TotalTests { get; set; }
    public List<string> FailedTests { get; set; } = new();
}

public class VulnerabilityReport
{
    public Guid Id { get; set; }
    public string Type { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string AffectedEndpoint { get; set; } = string.Empty;
    public string HttpMethod { get; set; } = string.Empty;
    public string? PayloadUsed { get; set; }
    public string? Evidence { get; set; }
    public string? Remediation { get; set; }
    public string? CweId { get; set; }
    public string? OwaspCategory { get; set; }
    public double ConfidenceScore { get; set; }
    public DateTime DiscoveredAt { get; set; }
    public Dictionary<string, object> Metadata { get; set; } = new();
}

public class RemediationPlan
{
    public List<string> ImmediateActions { get; set; } = new();
    public List<string> ShortTermActions { get; set; } = new();
    public List<string> LongTermActions { get; set; } = new();
    public Dictionary<string, string> RecommendationsByType { get; set; } = new();
    public string EstimatedEffort { get; set; } = string.Empty;
}