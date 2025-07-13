using Xunit;
using FluentAssertions;
using VaultScope.Core.Services;
using VaultScope.Core.Models;
using VaultScope.Core.Constants;

namespace VaultScope.Tests.Unit;

public class SecurityScoreCalculatorTests
{
    private readonly SecurityScoreCalculator _calculator;

    public SecurityScoreCalculatorTests()
    {
        _calculator = new SecurityScoreCalculator();
    }

    [Fact]
    public void Calculate_NoVulnerabilities_ReturnsAGrade()
    {
        // Arrange
        var scanResult = new ScanResult
        {
            Vulnerabilities = new List<Vulnerability>(),
            TestedEndpoints = new List<string> { "http://localhost/test" }
        };

        // Act
        var score = _calculator.Calculate(scanResult);

        // Assert
        score.Should().NotBeNull();
        score.Grade.Should().Be("A");
        score.OverallScore.Should().Be(100);
        score.CategoryScores.Should().NotBeEmpty();
        score.Strengths.Should().NotBeEmpty();
        score.Weaknesses.Should().BeEmpty();
    }

    [Fact]
    public void Calculate_CriticalVulnerability_ReducesScoreSignificantly()
    {
        // Arrange
        var scanResult = new ScanResult
        {
            Vulnerabilities = new List<Vulnerability>
            {
                new()
                {
                    Type = VulnerabilityTypes.SqlInjection,
                    Severity = VulnerabilitySeverity.Critical,
                    Title = "SQL Injection",
                    Description = "Critical SQL injection vulnerability",
                    AffectedEndpoint = "/api/users",
                    HttpMethod = "POST",
                    ConfidenceScore = 1.0
                }
            },
            TestedEndpoints = new List<string> { "http://localhost/api/users" }
        };

        // Act
        var score = _calculator.Calculate(scanResult);

        // Assert
        score.Should().NotBeNull();
        score.Grade.Should().BeOneOf("D", "F");
        score.OverallScore.Should().BeLessThan(50);
        score.Weaknesses.Should().NotBeEmpty();
    }

    [Fact]
    public void Calculate_MultipleHighVulnerabilities_ReducesScore()
    {
        // Arrange
        var scanResult = new ScanResult
        {
            Vulnerabilities = new List<Vulnerability>
            {
                new()
                {
                    Type = VulnerabilityTypes.CrossSiteScripting,
                    Severity = VulnerabilitySeverity.High,
                    Title = "XSS Vulnerability",
                    Description = "High severity XSS",
                    AffectedEndpoint = "/search",
                    HttpMethod = "GET",
                    ConfidenceScore = 0.9
                },
                new()
                {
                    Type = VulnerabilityTypes.MissingSecurityHeaders,
                    Severity = VulnerabilitySeverity.High,
                    Title = "Missing Security Headers",
                    Description = "Critical security headers missing",
                    AffectedEndpoint = "/",
                    HttpMethod = "GET",
                    ConfidenceScore = 1.0
                }
            },
            TestedEndpoints = new List<string> { "http://localhost/search", "http://localhost/" }
        };

        // Act
        var score = _calculator.Calculate(scanResult);

        // Assert
        score.Should().NotBeNull();
        score.Grade.Should().BeOneOf("C", "D");
        score.OverallScore.Should().BeLessThan(70);
        score.CategoryScores.Should().HaveCountGreaterThan(0);
    }

    [Fact]
    public void Calculate_OnlyLowVulnerabilities_MaintainsGoodScore()
    {
        // Arrange
        var scanResult = new ScanResult
        {
            Vulnerabilities = new List<Vulnerability>
            {
                new()
                {
                    Type = VulnerabilityTypes.MissingSecurityHeaders,
                    Severity = VulnerabilitySeverity.Low,
                    Title = "Missing Cache-Control Header",
                    Description = "Low severity header issue",
                    AffectedEndpoint = "/static",
                    HttpMethod = "GET",
                    ConfidenceScore = 0.8
                },
                new()
                {
                    Type = VulnerabilityTypes.SensitiveDataExposure,
                    Severity = VulnerabilitySeverity.Informational,
                    Title = "Server Banner Disclosure",
                    Description = "Server version disclosed",
                    AffectedEndpoint = "/",
                    HttpMethod = "HEAD",
                    ConfidenceScore = 1.0
                }
            },
            TestedEndpoints = new List<string> { "http://localhost/static", "http://localhost/" }
        };

        // Act
        var score = _calculator.Calculate(scanResult);

        // Assert
        score.Should().NotBeNull();
        score.Grade.Should().BeOneOf("A", "B");
        score.OverallScore.Should().BeGreaterThan(80);
    }

    [Fact]
    public void Calculate_MixedSeverityVulnerabilities_CalculatesAppropriateScore()
    {
        // Arrange
        var scanResult = new ScanResult
        {
            Vulnerabilities = new List<Vulnerability>
            {
                new()
                {
                    Type = VulnerabilityTypes.SqlInjection,
                    Severity = VulnerabilitySeverity.Medium,
                    Title = "Potential SQL Injection",
                    Description = "Medium severity SQL injection risk",
                    AffectedEndpoint = "/api/search",
                    HttpMethod = "POST",
                    ConfidenceScore = 0.7
                },
                new()
                {
                    Type = VulnerabilityTypes.CrossSiteScripting,
                    Severity = VulnerabilitySeverity.Low,
                    Title = "Reflected XSS",
                    Description = "Low severity XSS in error page",
                    AffectedEndpoint = "/error",
                    HttpMethod = "GET",
                    ConfidenceScore = 0.6
                },
                new()
                {
                    Type = VulnerabilityTypes.MissingSecurityHeaders,
                    Severity = VulnerabilitySeverity.Medium,
                    Title = "HSTS Not Configured",
                    Description = "HSTS header missing",
                    AffectedEndpoint = "/",
                    HttpMethod = "GET",
                    ConfidenceScore = 1.0
                }
            },
            TestedEndpoints = new List<string> { "http://localhost/api/search", "http://localhost/error", "http://localhost/" }
        };

        // Act
        var score = _calculator.Calculate(scanResult);

        // Assert
        score.Should().NotBeNull();
        score.Grade.Should().BeOneOf("B", "C");
        score.OverallScore.Should().BeInRange(60, 85);
        score.CategoryScores.Should().HaveCountGreaterThan(0);
        score.Recommendations.Should().NotBeEmpty();
    }

    [Fact]
    public void Calculate_ReturnsConsistentResults()
    {
        // Arrange
        var scanResult = new ScanResult
        {
            Vulnerabilities = new List<Vulnerability>
            {
                new()
                {
                    Type = VulnerabilityTypes.CrossSiteScripting,
                    Severity = VulnerabilitySeverity.Medium,
                    Title = "XSS",
                    Description = "XSS vulnerability",
                    AffectedEndpoint = "/test",
                    HttpMethod = "GET",
                    ConfidenceScore = 0.8
                }
            },
            TestedEndpoints = new List<string> { "http://localhost/test" }
        };

        // Act
        var score1 = _calculator.Calculate(scanResult);
        var score2 = _calculator.Calculate(scanResult);

        // Assert
        score1.OverallScore.Should().Be(score2.OverallScore);
        score1.Grade.Should().Be(score2.Grade);
    }

    [Fact]
    public void Calculate_HasAllRequiredProperties()
    {
        // Arrange
        var scanResult = new ScanResult
        {
            Vulnerabilities = new List<Vulnerability>
            {
                new()
                {
                    Type = VulnerabilityTypes.SqlInjection,
                    Severity = VulnerabilitySeverity.High,
                    Title = "SQL Injection",
                    Description = "SQL injection vulnerability",
                    AffectedEndpoint = "/api/test",
                    HttpMethod = "POST",
                    ConfidenceScore = 1.0
                }
            },
            TestedEndpoints = new List<string> { "http://localhost/api/test" }
        };

        // Act
        var score = _calculator.Calculate(scanResult);

        // Assert
        score.Should().NotBeNull();
        score.Grade.Should().NotBeNullOrEmpty();
        score.OverallScore.Should().BeInRange(0, 100);
        score.CategoryScores.Should().NotBeNull();
        score.Strengths.Should().NotBeNull();
        score.Weaknesses.Should().NotBeNull();
        score.Recommendations.Should().NotBeNull();
    }
}