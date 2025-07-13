using System.Text;
using System.Text.Json;
using VaultScope.Core.Models;
using VaultScope.Core.Interfaces;
using VaultScope.Infrastructure.Reporting;
using Xunit;
using FluentAssertions;

namespace VaultScope.Tests.Integration;

public class ReportGenerationTests : IDisposable
{
    private readonly string _tempDirectory;

    public ReportGenerationTests()
    {
        _tempDirectory = Path.Combine(Path.GetTempPath(), "VaultScopeTests", Guid.NewGuid().ToString());
        Directory.CreateDirectory(_tempDirectory);
    }

    [Fact]
    public async Task HtmlReportGenerator_GenerateAsync_ShouldProduceValidHtml()
    {
        // Arrange
        var generator = new HtmlReportGenerator();
        var scanResult = CreateTestScanResult();
        var options = CreateReportOptions();

        // Act
        var result = await generator.GenerateAsync(scanResult, options);

        // Assert
        result.Should().NotBeNull();
        result.Should().NotBeEmpty();

        var htmlContent = Encoding.UTF8.GetString(result);
        htmlContent.Should().Contain("<!DOCTYPE html>");
        htmlContent.Should().Contain("<html");
        htmlContent.Should().Contain("</html>");
        htmlContent.Should().Contain("Security Assessment Report");
        htmlContent.Should().Contain(scanResult.TargetUrl);
        htmlContent.Should().Contain("Critical SQL Injection");
        htmlContent.Should().Contain("Reflected XSS");
        htmlContent.Should().Contain("Overall Score: 75");
    }

    [Fact]
    public async Task HtmlReportGenerator_SaveToFileAsync_ShouldCreateValidFile()
    {
        // Arrange
        var generator = new HtmlReportGenerator();
        var scanResult = CreateTestScanResult();
        var options = CreateReportOptions();
        var filePath = Path.Combine(_tempDirectory, "test-report.html");

        // Act
        await generator.SaveToFileAsync(scanResult, filePath, options);

        // Assert
        File.Exists(filePath).Should().BeTrue();
        
        var content = await File.ReadAllTextAsync(filePath);
        content.Should().Contain("<!DOCTYPE html>");
        content.Should().Contain(scanResult.TargetUrl);
        content.Should().Contain("Security Assessment Report");
    }

    [Fact]
    public async Task HtmlReportGenerator_WithAllSections_ShouldIncludeAllContent()
    {
        // Arrange
        var generator = new HtmlReportGenerator();
        var scanResult = CreateTestScanResult();
        var options = new ReportOptions
        {
            Title = "Complete Security Report",
            CompanyName = "Test Company",
            IncludeExecutiveSummary = true,
            IncludeSecurityScore = true,
            IncludeCharts = true,
            IncludeDetailedFindings = true,
            IncludeTimeline = true,
            IncludeRemediation = true
        };

        // Act
        var result = await generator.GenerateAsync(scanResult, options);

        // Assert
        var htmlContent = Encoding.UTF8.GetString(result);
        
        htmlContent.Should().Contain("Complete Security Report");
        htmlContent.Should().Contain("Test Company");
        htmlContent.Should().Contain("Executive Summary");
        htmlContent.Should().Contain("Security Score");
        htmlContent.Should().Contain("Vulnerability Analysis");
        htmlContent.Should().Contain("Detailed Findings");
        htmlContent.Should().Contain("Scan Timeline");
        htmlContent.Should().Contain("Remediation Recommendations");
        htmlContent.Should().Contain("Chart.js"); // Charts should be included
    }

    [Fact]
    public async Task HtmlReportGenerator_WithMinimalSections_ShouldExcludeOptionalContent()
    {
        // Arrange
        var generator = new HtmlReportGenerator();
        var scanResult = CreateTestScanResult();
        var options = new ReportOptions
        {
            Title = "Minimal Report",
            IncludeExecutiveSummary = false,
            IncludeSecurityScore = false,
            IncludeCharts = false,
            IncludeDetailedFindings = true, // Only include this
            IncludeTimeline = false,
            IncludeRemediation = false
        };

        // Act
        var result = await generator.GenerateAsync(scanResult, options);

        // Assert
        var htmlContent = Encoding.UTF8.GetString(result);
        
        htmlContent.Should().Contain("Minimal Report");
        htmlContent.Should().Contain("Detailed Findings");
        htmlContent.Should().NotContain("Executive Summary");
        htmlContent.Should().NotContain("Security Score");
        htmlContent.Should().NotContain("Vulnerability Analysis");
        htmlContent.Should().NotContain("Scan Timeline");
        htmlContent.Should().NotContain("Remediation Recommendations");
    }

    [Fact]
    public async Task JsonReportGenerator_GenerateAsync_ShouldProduceValidJson()
    {
        // Arrange
        var generator = new JsonReportGenerator();
        var scanResult = CreateTestScanResult();
        var options = CreateReportOptions();

        // Act
        var result = await generator.GenerateAsync(scanResult, options);

        // Assert
        result.Should().NotBeNull();
        result.Should().NotBeEmpty();

        var jsonContent = Encoding.UTF8.GetString(result);
        
        // Should be valid JSON
        var parsed = JsonDocument.Parse(jsonContent);
        parsed.Should().NotBeNull();

        // Check for expected properties
        jsonContent.Should().Contain("targetUrl");
        jsonContent.Should().Contain("vulnerabilities");
        jsonContent.Should().Contain("securityScore");
        jsonContent.Should().Contain(scanResult.TargetUrl);
    }

    [Fact]
    public async Task JsonReportGenerator_SaveToFileAsync_ShouldCreateValidJsonFile()
    {
        // Arrange
        var generator = new JsonReportGenerator();
        var scanResult = CreateTestScanResult();
        var options = CreateReportOptions();
        var filePath = Path.Combine(_tempDirectory, "test-report.json");

        // Act
        await generator.SaveToFileAsync(scanResult, filePath, options);

        // Assert
        File.Exists(filePath).Should().BeTrue();
        
        var content = await File.ReadAllTextAsync(filePath);
        var parsed = JsonDocument.Parse(content);
        parsed.Should().NotBeNull();
        
        content.Should().Contain(scanResult.TargetUrl);
        content.Should().Contain("vulnerabilities");
    }

    [Fact]
    public async Task JsonReportGenerator_ShouldSerializeAllScanResultProperties()
    {
        // Arrange
        var generator = new JsonReportGenerator();
        var scanResult = CreateTestScanResult();
        var options = CreateReportOptions();

        // Act
        var result = await generator.GenerateAsync(scanResult, options);

        // Assert
        var jsonContent = Encoding.UTF8.GetString(result);
        using var document = JsonDocument.Parse(jsonContent);
        var root = document.RootElement;

        // Verify all major properties are present
        root.GetProperty("id").GetGuid().Should().Be(scanResult.Id);
        root.GetProperty("targetUrl").GetString().Should().Be(scanResult.TargetUrl);
        root.GetProperty("status").GetString().Should().NotBeEmpty();
        
        var vulnerabilities = root.GetProperty("vulnerabilities");
        vulnerabilities.GetArrayLength().Should().Be(2);
        
        var securityScore = root.GetProperty("securityScore");
        securityScore.GetProperty("overallScore").GetDouble().Should().Be(75.5);
        
        var testedEndpoints = root.GetProperty("testedEndpoints");
        testedEndpoints.GetArrayLength().Should().Be(3);
    }

    [Fact]
    public async Task PdfReportGenerator_GenerateAsync_ShouldProducePdfBytes()
    {
        // Arrange
        var generator = new PdfReportGenerator();
        var scanResult = CreateTestScanResult();
        var options = CreateReportOptions();

        // Act
        var result = await generator.GenerateAsync(scanResult, options);

        // Assert
        result.Should().NotBeNull();
        result.Should().NotBeEmpty();
        result.Length.Should().BeGreaterThan(1000); // PDF should be substantial

        // Check PDF signature (PDF files start with %PDF)
        var pdfSignature = Encoding.ASCII.GetString(result.Take(4).ToArray());
        pdfSignature.Should().Be("%PDF");
    }

    [Fact]
    public async Task PdfReportGenerator_SaveToFileAsync_ShouldCreateValidPdfFile()
    {
        // Arrange
        var generator = new PdfReportGenerator();
        var scanResult = CreateTestScanResult();
        var options = CreateReportOptions();
        var filePath = Path.Combine(_tempDirectory, "test-report.pdf");

        // Act
        await generator.SaveToFileAsync(scanResult, filePath, options);

        // Assert
        File.Exists(filePath).Should().BeTrue();
        
        var fileInfo = new FileInfo(filePath);
        fileInfo.Length.Should().BeGreaterThan(1000); // PDF should be substantial

        // Verify it's a valid PDF file
        var bytes = await File.ReadAllBytesAsync(filePath);
        var pdfSignature = Encoding.ASCII.GetString(bytes.Take(4).ToArray());
        pdfSignature.Should().Be("%PDF");
    }

    [Fact]
    public async Task PdfReportGenerator_WithVariousVulnerabilitySeverities_ShouldGenerateCorrectly()
    {
        // Arrange
        var generator = new PdfReportGenerator();
        var scanResult = CreateTestScanResult();
        
        // Add vulnerabilities of different severities
        scanResult.Vulnerabilities.Add(new Vulnerability
        {
            Type = "Medium Issue",
            Severity = VulnerabilitySeverity.Medium,
            Title = "Medium Severity Issue",
            AffectedEndpoint = "http://localhost:3000/api/medium"
        });
        
        scanResult.Vulnerabilities.Add(new Vulnerability
        {
            Type = "Low Issue",
            Severity = VulnerabilitySeverity.Low,
            Title = "Low Severity Issue",
            AffectedEndpoint = "http://localhost:3000/api/low"
        });

        var options = CreateReportOptions();

        // Act
        var result = await generator.GenerateAsync(scanResult, options);

        // Assert
        result.Should().NotBeNull();
        result.Should().NotBeEmpty();
        
        // PDF should be generated without errors
        var pdfSignature = Encoding.ASCII.GetString(result.Take(4).ToArray());
        pdfSignature.Should().Be("%PDF");
    }

    [Fact]
    public async Task AllReportGenerators_ShouldHaveUniqueFormats()
    {
        // Arrange
        var htmlGenerator = new HtmlReportGenerator();
        var jsonGenerator = new JsonReportGenerator();
        var pdfGenerator = new PdfReportGenerator();

        // Act & Assert
        htmlGenerator.Format.Should().Be(ReportFormat.Html);
        jsonGenerator.Format.Should().Be(ReportFormat.Json);
        pdfGenerator.Format.Should().Be(ReportFormat.Pdf);

        // All formats should be different
        var formats = new[] { htmlGenerator.Format, jsonGenerator.Format, pdfGenerator.Format };
        formats.Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public async Task ReportGeneration_WithEmptyVulnerabilities_ShouldStillGenerate()
    {
        // Arrange
        var scanResult = CreateTestScanResult();
        scanResult.Vulnerabilities.Clear(); // No vulnerabilities
        var options = CreateReportOptions();

        var htmlGenerator = new HtmlReportGenerator();
        var jsonGenerator = new JsonReportGenerator();
        var pdfGenerator = new PdfReportGenerator();

        // Act & Assert
        var htmlResult = await htmlGenerator.GenerateAsync(scanResult, options);
        htmlResult.Should().NotBeEmpty();
        var htmlContent = Encoding.UTF8.GetString(htmlResult);
        htmlContent.Should().Contain("No vulnerabilities detected");

        var jsonResult = await jsonGenerator.GenerateAsync(scanResult, options);
        jsonResult.Should().NotBeEmpty();
        var jsonContent = Encoding.UTF8.GetString(jsonResult);
        using var document = JsonDocument.Parse(jsonContent);
        document.RootElement.GetProperty("vulnerabilities").GetArrayLength().Should().Be(0);

        var pdfResult = await pdfGenerator.GenerateAsync(scanResult, options);
        pdfResult.Should().NotBeEmpty();
        var pdfSignature = Encoding.ASCII.GetString(pdfResult.Take(4).ToArray());
        pdfSignature.Should().Be("%PDF");
    }

    [Fact]
    public async Task ReportGeneration_WithLargeDataset_ShouldHandleCorrectly()
    {
        // Arrange
        var scanResult = CreateTestScanResult();
        
        // Add many vulnerabilities to test performance
        for (int i = 0; i < 50; i++)
        {
            scanResult.Vulnerabilities.Add(new Vulnerability
            {
                Type = $"Test Vulnerability {i}",
                Severity = (VulnerabilitySeverity)(i % 5),
                Title = $"Test Issue {i}",
                Description = $"This is test vulnerability number {i} with a longer description to test handling of large text content.",
                AffectedEndpoint = $"http://localhost:3000/api/test{i}",
                HttpMethod = "GET",
                Evidence = $"Long evidence text for vulnerability {i}. " + string.Join(" ", Enumerable.Repeat("Evidence data", 10)),
                Remediation = $"Detailed remediation steps for issue {i}. " + string.Join(" ", Enumerable.Repeat("Fix this", 5))
            });
        }

        // Add many endpoints
        for (int i = 0; i < 100; i++)
        {
            scanResult.TestedEndpoints.Add($"http://localhost:3000/api/endpoint{i}");
        }

        var options = CreateReportOptions();

        // Act & Assert
        var htmlGenerator = new HtmlReportGenerator();
        var htmlResult = await htmlGenerator.GenerateAsync(scanResult, options);
        htmlResult.Should().NotBeEmpty();

        var jsonGenerator = new JsonReportGenerator();
        var jsonResult = await jsonGenerator.GenerateAsync(scanResult, options);
        jsonResult.Should().NotBeEmpty();

        var pdfGenerator = new PdfReportGenerator();
        var pdfResult = await pdfGenerator.GenerateAsync(scanResult, options);
        pdfResult.Should().NotBeEmpty();
    }

    private ScanResult CreateTestScanResult()
    {
        return new ScanResult
        {
            Id = Guid.NewGuid(),
            TargetUrl = "http://localhost:3000",
            StartTime = DateTime.UtcNow.AddMinutes(-30),
            EndTime = DateTime.UtcNow,
            Status = ScanStatus.Completed,
            TotalRequestsMade = 25,
            Vulnerabilities = new List<Vulnerability>
            {
                new Vulnerability
                {
                    Type = "SQL Injection",
                    Severity = VulnerabilitySeverity.Critical,
                    Title = "Critical SQL Injection",
                    Description = "SQL injection vulnerability in user input",
                    AffectedEndpoint = "http://localhost:3000/api/users",
                    HttpMethod = "POST",
                    PayloadUsed = "'; DROP TABLE users; --",
                    Evidence = "MySQL error in response",
                    Remediation = "Use parameterized queries",
                    CweId = "CWE-89",
                    OwaspCategory = "A03:2021 - Injection",
                    ConfidenceScore = 0.95
                },
                new Vulnerability
                {
                    Type = "Cross-Site Scripting (XSS)",
                    Severity = VulnerabilitySeverity.High,
                    Title = "Reflected XSS",
                    Description = "XSS vulnerability in search parameter",
                    AffectedEndpoint = "http://localhost:3000/api/search",
                    HttpMethod = "GET",
                    PayloadUsed = "<script>alert('xss')</script>",
                    Evidence = "Script tag reflected in response",
                    Remediation = "Encode user input",
                    CweId = "CWE-79",
                    OwaspCategory = "A03:2021 - Injection",
                    ConfidenceScore = 0.90
                }
            },
            SecurityScore = new SecurityScore
            {
                OverallScore = 75.5,
                Grade = "B",
                CategoryScores = new Dictionary<string, CategoryScore>
                {
                    ["Input Validation"] = new CategoryScore
                    {
                        Category = "Input Validation",
                        Score = 60.0,
                        TestsPassed = 3,
                        TotalTests = 5
                    },
                    ["Authentication"] = new CategoryScore
                    {
                        Category = "Authentication",
                        Score = 85.0,
                        TestsPassed = 4,
                        TotalTests = 5
                    }
                },
                Strengths = new List<string> { "Strong authentication", "Good HTTPS configuration" },
                Weaknesses = new List<string> { "Input validation issues", "Missing rate limiting" },
                TestResults = new Dictionary<string, bool>
                {
                    ["SQL Injection Test"] = false,
                    ["XSS Test"] = false,
                    ["Auth Test"] = true,
                    ["HTTPS Test"] = true
                }
            },
            TestedEndpoints = new List<string>
            {
                "http://localhost:3000",
                "http://localhost:3000/api/users",
                "http://localhost:3000/api/search"
            },
            VulnerabilityCountBySeverity = new Dictionary<string, int>
            {
                ["Critical"] = 1,
                ["High"] = 1,
                ["Medium"] = 0,
                ["Low"] = 0
            }
        };
    }

    private ReportOptions CreateReportOptions()
    {
        return new ReportOptions
        {
            Title = "Security Assessment Report",
            CompanyName = "VaultScope Security",
            IncludeExecutiveSummary = true,
            IncludeSecurityScore = true,
            IncludeCharts = true,
            IncludeDetailedFindings = true,
            IncludeTimeline = true,
            IncludeRemediation = true
        };
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDirectory))
        {
            Directory.Delete(_tempDirectory, recursive: true);
        }
    }
}