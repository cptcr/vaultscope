using VaultScope.Core.Models;

namespace VaultScope.Core.Services;

public class SecurityScoreCalculator
{
    private readonly Dictionary<VulnerabilitySeverity, int> _severityWeights = new()
    {
        [VulnerabilitySeverity.Critical] = 40,
        [VulnerabilitySeverity.High] = 20,
        [VulnerabilitySeverity.Medium] = 10,
        [VulnerabilitySeverity.Low] = 5,
        [VulnerabilitySeverity.Informational] = 1
    };
    
    private readonly Dictionary<string, double> _categoryWeights = new()
    {
        ["Injection"] = 1.0,
        ["Authentication"] = 1.0,
        ["Access Control"] = 0.9,
        ["Configuration"] = 0.8,
        ["Data Protection"] = 0.9,
        ["Implementation"] = 0.7
    };
    
    public SecurityScore Calculate(ScanResult scanResult)
    {
        var score = new SecurityScore
        {
            CalculatedAt = DateTime.UtcNow
        };
        
        // Base score starts at 100
        double baseScore = 100.0;
        
        // Calculate vulnerability impact
        var vulnerabilityImpact = CalculateVulnerabilityImpact(scanResult.Vulnerabilities);
        baseScore -= vulnerabilityImpact;
        
        // Calculate category scores
        score.CategoryScores = CalculateCategoryScores(scanResult);
        
        // Calculate strengths and weaknesses
        AnalyzeStrengthsAndWeaknesses(scanResult, score);
        
        // Generate recommendations
        score.Recommendations = GenerateRecommendations(scanResult, score);
        
        // Ensure score is within bounds
        score.OverallScore = Math.Max(0, Math.Min(100, baseScore));
        score.Grade = SecurityScore.CalculateGrade(score.OverallScore);
        
        return score;
    }
    
    private double CalculateVulnerabilityImpact(List<Vulnerability> vulnerabilities)
    {
        double impact = 0;
        
        foreach (var vuln in vulnerabilities)
        {
            var weight = _severityWeights[vuln.Severity];
            var confidence = vuln.ConfidenceScore;
            
            // Apply category weight if applicable
            var categoryWeight = 1.0;
            foreach (var category in _categoryWeights.Keys)
            {
                if (vuln.Type.Contains(category, StringComparison.OrdinalIgnoreCase))
                {
                    categoryWeight = _categoryWeights[category];
                    break;
                }
            }
            
            impact += weight * confidence * categoryWeight;
        }
        
        // Apply diminishing returns for multiple vulnerabilities
        if (vulnerabilities.Count > 10)
        {
            impact *= 1 + (vulnerabilities.Count - 10) * 0.05;
        }
        
        return Math.Min(100, impact);
    }
    
    private Dictionary<string, CategoryScore> CalculateCategoryScores(ScanResult scanResult)
    {
        var categories = new Dictionary<string, CategoryScore>
        {
            ["Injection Protection"] = CalculateInjectionScore(scanResult),
            ["Authentication & Authorization"] = CalculateAuthScore(scanResult),
            ["Data Protection"] = CalculateDataProtectionScore(scanResult),
            ["Security Configuration"] = CalculateConfigurationScore(scanResult),
            ["Input Validation"] = CalculateInputValidationScore(scanResult),
            ["Error Handling"] = CalculateErrorHandlingScore(scanResult)
        };
        
        return categories;
    }
    
    private CategoryScore CalculateInjectionScore(ScanResult scanResult)
    {
        var injectionTypes = new[] { "SQL", "XSS", "XXE", "Command" };
        var injectionVulns = scanResult.Vulnerabilities
            .Where(v => injectionTypes.Any(t => v.Type.Contains(t, StringComparison.OrdinalIgnoreCase)))
            .ToList();
        
        var totalTests = scanResult.TestedEndpoints.Count * injectionTypes.Length;
        var failedTests = injectionVulns.Count;
        var passed = totalTests - failedTests;
        
        return new CategoryScore
        {
            Category = "Injection Protection",
            Score = totalTests > 0 ? (double)passed / totalTests * 100 : 100,
            TestsPassed = passed,
            TotalTests = totalTests,
            FailedTests = injectionVulns.Select(v => v.Title).Distinct().ToList()
        };
    }
    
    private CategoryScore CalculateAuthScore(ScanResult scanResult)
    {
        var authVulns = scanResult.Vulnerabilities
            .Where(v => v.Type.Contains("Auth", StringComparison.OrdinalIgnoreCase))
            .ToList();
        
        var totalTests = scanResult.TestedEndpoints.Count * 3; // Basic auth tests
        var failedTests = authVulns.Count;
        var passed = totalTests - failedTests;
        
        return new CategoryScore
        {
            Category = "Authentication & Authorization",
            Score = totalTests > 0 ? (double)passed / totalTests * 100 : 100,
            TestsPassed = passed,
            TotalTests = totalTests,
            FailedTests = authVulns.Select(v => v.Title).Distinct().ToList()
        };
    }
    
    private CategoryScore CalculateDataProtectionScore(ScanResult scanResult)
    {
        var dataVulns = scanResult.Vulnerabilities
            .Where(v => v.Type.Contains("Data", StringComparison.OrdinalIgnoreCase) ||
                       v.Type.Contains("Exposure", StringComparison.OrdinalIgnoreCase))
            .ToList();
        
        var totalTests = scanResult.TestedEndpoints.Count * 2;
        var failedTests = dataVulns.Count;
        var passed = totalTests - failedTests;
        
        return new CategoryScore
        {
            Category = "Data Protection",
            Score = totalTests > 0 ? (double)passed / totalTests * 100 : 100,
            TestsPassed = passed,
            TotalTests = totalTests,
            FailedTests = dataVulns.Select(v => v.Title).Distinct().ToList()
        };
    }
    
    private CategoryScore CalculateConfigurationScore(ScanResult scanResult)
    {
        var configVulns = scanResult.Vulnerabilities
            .Where(v => v.Type.Contains("Configuration", StringComparison.OrdinalIgnoreCase) ||
                       v.Type.Contains("Headers", StringComparison.OrdinalIgnoreCase))
            .ToList();
        
        var totalTests = scanResult.TestedEndpoints.Count * 5; // Header checks
        var failedTests = configVulns.Count;
        var passed = totalTests - failedTests;
        
        return new CategoryScore
        {
            Category = "Security Configuration",
            Score = totalTests > 0 ? (double)passed / totalTests * 100 : 100,
            TestsPassed = passed,
            TotalTests = totalTests,
            FailedTests = configVulns.Select(v => v.Title).Distinct().ToList()
        };
    }
    
    private CategoryScore CalculateInputValidationScore(ScanResult scanResult)
    {
        var validationVulns = scanResult.Vulnerabilities
            .Where(v => v.Type.Contains("Injection", StringComparison.OrdinalIgnoreCase) ||
                       v.Type.Contains("Traversal", StringComparison.OrdinalIgnoreCase))
            .ToList();
        
        var totalTests = scanResult.TestedEndpoints.Count * 4;
        var failedTests = validationVulns.Count;
        var passed = totalTests - failedTests;
        
        return new CategoryScore
        {
            Category = "Input Validation",
            Score = totalTests > 0 ? (double)passed / totalTests * 100 : 100,
            TestsPassed = passed,
            TotalTests = totalTests,
            FailedTests = validationVulns.Select(v => v.Title).Distinct().ToList()
        };
    }
    
    private CategoryScore CalculateErrorHandlingScore(ScanResult scanResult)
    {
        // Look for information disclosure through errors
        var errorVulns = scanResult.Vulnerabilities
            .Where(v => v.Evidence?.Contains("error", StringComparison.OrdinalIgnoreCase) == true ||
                       v.Evidence?.Contains("stack trace", StringComparison.OrdinalIgnoreCase) == true)
            .ToList();
        
        var totalTests = scanResult.TestedEndpoints.Count;
        var failedTests = errorVulns.Count;
        var passed = totalTests - failedTests;
        
        return new CategoryScore
        {
            Category = "Error Handling",
            Score = totalTests > 0 ? (double)passed / totalTests * 100 : 100,
            TestsPassed = passed,
            TotalTests = totalTests,
            FailedTests = errorVulns.Select(v => "Information disclosure through error messages").Distinct().ToList()
        };
    }
    
    private void AnalyzeStrengthsAndWeaknesses(ScanResult scanResult, SecurityScore score)
    {
        // Identify strengths
        score.Strengths = new List<string>();
        
        foreach (var category in score.CategoryScores.Values)
        {
            if (category.Score >= 90)
            {
                score.Strengths.Add($"Excellent {category.Category.ToLower()}");
            }
            else if (category.Score >= 80)
            {
                score.Strengths.Add($"Good {category.Category.ToLower()}");
            }
        }
        
        if (!scanResult.Vulnerabilities.Any(v => v.Severity == VulnerabilitySeverity.Critical))
        {
            score.Strengths.Add("No critical vulnerabilities detected");
        }
        
        if (scanResult.Vulnerabilities.Count(v => v.Type.Contains("Rate", StringComparison.OrdinalIgnoreCase)) == 0)
        {
            score.Strengths.Add("Proper rate limiting implemented");
        }
        
        // Identify weaknesses
        score.Weaknesses = new List<string>();
        
        foreach (var category in score.CategoryScores.Values)
        {
            if (category.Score < 50)
            {
                score.Weaknesses.Add($"Poor {category.Category.ToLower()}");
            }
            else if (category.Score < 70)
            {
                score.Weaknesses.Add($"Weak {category.Category.ToLower()}");
            }
        }
        
        var criticalCount = scanResult.Vulnerabilities.Count(v => v.Severity == VulnerabilitySeverity.Critical);
        if (criticalCount > 0)
        {
            score.Weaknesses.Add($"{criticalCount} critical vulnerabilities require immediate attention");
        }
        
        var highCount = scanResult.Vulnerabilities.Count(v => v.Severity == VulnerabilitySeverity.High);
        if (highCount > 2)
        {
            score.Weaknesses.Add($"{highCount} high-severity vulnerabilities present significant risk");
        }
    }
    
    private List<string> GenerateRecommendations(ScanResult scanResult, SecurityScore score)
    {
        var recommendations = new List<string>();
        
        // Priority recommendations based on severity
        if (scanResult.Vulnerabilities.Any(v => v.Severity == VulnerabilitySeverity.Critical))
        {
            recommendations.Add("Immediately address all critical vulnerabilities");
        }
        
        // Category-specific recommendations
        foreach (var category in score.CategoryScores.Values.Where(c => c.Score < 70))
        {
            switch (category.Category)
            {
                case "Injection Protection":
                    recommendations.Add("Implement parameterized queries and input validation framework");
                    break;
                case "Authentication & Authorization":
                    recommendations.Add("Review and strengthen authentication mechanisms");
                    break;
                case "Security Configuration":
                    recommendations.Add("Configure comprehensive security headers on all responses");
                    break;
                case "Data Protection":
                    recommendations.Add("Implement encryption for sensitive data in transit and at rest");
                    break;
                case "Input Validation":
                    recommendations.Add("Deploy strict input validation with whitelist approach");
                    break;
            }
        }
        
        // General recommendations
        if (score.OverallScore < 80)
        {
            recommendations.Add("Consider security code review and penetration testing");
        }
        
        if (scanResult.Vulnerabilities.Count > 10)
        {
            recommendations.Add("Implement a secure software development lifecycle (SSDLC)");
        }
        
        recommendations.Add("Schedule regular security assessments");
        recommendations.Add("Provide security training to development team");
        
        return recommendations.Take(5).ToList();
    }
}