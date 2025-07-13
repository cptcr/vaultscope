using Microsoft.Extensions.Logging;
using Moq;
using VaultScope.Core.Interfaces;
using VaultScope.Core.Models;
using VaultScope.Core.Services;
using Xunit;
using FluentAssertions;
using System.Net;

namespace VaultScope.Tests.Integration;

public class SecurityScannerServiceTests
{
    private readonly Mock<IUrlValidator> _urlValidatorMock;
    private readonly Mock<ILogger<SecurityScannerService>> _loggerMock;
    private readonly Mock<IVulnerabilityDetector> _sqlDetectorMock;
    private readonly Mock<IVulnerabilityDetector> _xssDetectorMock;
    private readonly SecurityScoreCalculator _scoreCalculator;
    private readonly SecurityScannerService _securityScanner;

    public SecurityScannerServiceTests()
    {
        _urlValidatorMock = new Mock<IUrlValidator>();
        _loggerMock = new Mock<ILogger<SecurityScannerService>>();
        _sqlDetectorMock = new Mock<IVulnerabilityDetector>();
        _xssDetectorMock = new Mock<IVulnerabilityDetector>();
        _scoreCalculator = new SecurityScoreCalculator();

        // Setup SQL detector
        _sqlDetectorMock.Setup(x => x.Type).Returns(VulnerabilityType.SqlInjection);
        _sqlDetectorMock.Setup(x => x.Name).Returns("SQL Injection Detector");
        _sqlDetectorMock.Setup(x => x.Description).Returns("Test SQL detector");
        _sqlDetectorMock.Setup(x => x.Priority).Returns(100);
        _sqlDetectorMock.Setup(x => x.IsApplicable(It.IsAny<string>(), It.IsAny<HttpMethod>())).Returns(true);

        // Setup XSS detector
        _xssDetectorMock.Setup(x => x.Type).Returns(VulnerabilityType.CrossSiteScripting);
        _xssDetectorMock.Setup(x => x.Name).Returns("XSS Detector");
        _xssDetectorMock.Setup(x => x.Description).Returns("Test XSS detector");
        _xssDetectorMock.Setup(x => x.Priority).Returns(90);
        _xssDetectorMock.Setup(x => x.IsApplicable(It.IsAny<string>(), It.IsAny<HttpMethod>())).Returns(true);

        var detectors = new List<IVulnerabilityDetector> { _sqlDetectorMock.Object, _xssDetectorMock.Object };
        _securityScanner = new SecurityScannerService(detectors, _urlValidatorMock.Object, _loggerMock.Object, _scoreCalculator);
    }

    [Fact]
    public async Task ScanAsync_ValidConfiguration_ShouldReturnScanResult()
    {
        // Arrange
        var targetUrl = "http://localhost:3000";
        var configuration = new ScanConfiguration
        {
            TargetUrl = targetUrl,
            Depth = ScanDepth.Quick,
            VulnerabilityTypes = new List<VulnerabilityType> { VulnerabilityType.SqlInjection, VulnerabilityType.CrossSiteScripting },
            MaxConcurrentRequests = 2,
            MaxRequestsPerSecond = 5
        };

        var validationResult = new UrlValidationResult
        {
            IsValid = true,
            IsLocalhost = true,
            ErrorMessage = null
        };

        var sqlVulnerability = new Vulnerability
        {
            Type = "SQL Injection",
            Severity = VulnerabilitySeverity.Critical,
            Title = "SQL Injection Found",
            Description = "Critical SQL injection vulnerability",
            AffectedEndpoint = targetUrl,
            HttpMethod = "GET"
        };

        _urlValidatorMock.Setup(x => x.Validate(targetUrl)).Returns(validationResult);
        _sqlDetectorMock.Setup(x => x.DetectAsync(It.IsAny<string>(), It.IsAny<HttpMethod>(), It.IsAny<AuthenticationResult>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<Vulnerability> { sqlVulnerability });
        _xssDetectorMock.Setup(x => x.DetectAsync(It.IsAny<string>(), It.IsAny<HttpMethod>(), It.IsAny<AuthenticationResult>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<Vulnerability>());

        // Act
        var result = await _securityScanner.ScanAsync(configuration);

        // Assert
        result.Should().NotBeNull();
        result.TargetUrl.Should().Be(targetUrl);
        result.Status.Should().Be(ScanStatus.Completed);
        result.Vulnerabilities.Should().HaveCount(1);
        result.Vulnerabilities[0].Type.Should().Be("SQL Injection");
        result.Vulnerabilities[0].Severity.Should().Be(VulnerabilitySeverity.Critical);
        result.SecurityScore.Should().NotBeNull();
        result.EndTime.Should().NotBeNull();
        result.TestedEndpoints.Should().NotBeEmpty();
    }

    [Fact]
    public async Task ScanAsync_InvalidUrl_ShouldThrowArgumentException()
    {
        // Arrange
        var invalidUrl = "http://external-site.com";
        var configuration = new ScanConfiguration
        {
            TargetUrl = invalidUrl,
            Depth = ScanDepth.Quick,
            VulnerabilityTypes = new List<VulnerabilityType> { VulnerabilityType.SqlInjection }
        };

        var validationResult = new UrlValidationResult
        {
            IsValid = false,
            IsLocalhost = false,
            ErrorMessage = "URL is not localhost"
        };

        _urlValidatorMock.Setup(x => x.Validate(invalidUrl)).Returns(validationResult);

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(() => _securityScanner.ScanAsync(configuration));
    }

    [Fact]
    public async Task QuickScanAsync_ValidUrl_ShouldReturnScanResult()
    {
        // Arrange
        var targetUrl = "http://localhost:8080";
        var validationResult = new UrlValidationResult
        {
            IsValid = true,
            IsLocalhost = true,
            ErrorMessage = null
        };

        _urlValidatorMock.Setup(x => x.Validate(targetUrl)).Returns(validationResult);
        _sqlDetectorMock.Setup(x => x.DetectAsync(It.IsAny<string>(), It.IsAny<HttpMethod>(), It.IsAny<AuthenticationResult>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<Vulnerability>());
        _xssDetectorMock.Setup(x => x.DetectAsync(It.IsAny<string>(), It.IsAny<HttpMethod>(), It.IsAny<AuthenticationResult>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<Vulnerability>());

        // Act
        var result = await _securityScanner.QuickScanAsync(targetUrl);

        // Assert
        result.Should().NotBeNull();
        result.TargetUrl.Should().Be(targetUrl);
        result.Status.Should().Be(ScanStatus.Completed);
        result.SecurityScore.Should().NotBeNull();
    }

    [Fact]
    public async Task ScanAsync_ShouldRaiseProgressChangedEvents()
    {
        // Arrange
        var targetUrl = "http://localhost:3000";
        var configuration = new ScanConfiguration
        {
            TargetUrl = targetUrl,
            Depth = ScanDepth.Quick,
            VulnerabilityTypes = new List<VulnerabilityType> { VulnerabilityType.SqlInjection },
            MaxConcurrentRequests = 1,
            MaxRequestsPerSecond = 10
        };

        var validationResult = new UrlValidationResult
        {
            IsValid = true,
            IsLocalhost = true,
            ErrorMessage = null
        };

        _urlValidatorMock.Setup(x => x.Validate(targetUrl)).Returns(validationResult);
        _sqlDetectorMock.Setup(x => x.DetectAsync(It.IsAny<string>(), It.IsAny<HttpMethod>(), It.IsAny<AuthenticationResult>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<Vulnerability>());

        var progressEvents = new List<ScanProgressEventArgs>();
        _securityScanner.ProgressChanged += (sender, args) => progressEvents.Add(args);

        // Act
        await _securityScanner.ScanAsync(configuration);

        // Assert
        progressEvents.Should().NotBeEmpty();
        progressEvents.Should().Contain(e => e.ProgressPercentage > 0);
    }

    [Fact]
    public async Task ScanAsync_ShouldRaiseVulnerabilityDetectedEvents()
    {
        // Arrange
        var targetUrl = "http://localhost:3000";
        var configuration = new ScanConfiguration
        {
            TargetUrl = targetUrl,
            Depth = ScanDepth.Quick,
            VulnerabilityTypes = new List<VulnerabilityType> { VulnerabilityType.SqlInjection },
            MaxConcurrentRequests = 1,
            MaxRequestsPerSecond = 10
        };

        var validationResult = new UrlValidationResult
        {
            IsValid = true,
            IsLocalhost = true,
            ErrorMessage = null
        };

        var vulnerability = new Vulnerability
        {
            Type = "SQL Injection",
            Severity = VulnerabilitySeverity.High,
            Title = "Test vulnerability",
            AffectedEndpoint = targetUrl
        };

        _urlValidatorMock.Setup(x => x.Validate(targetUrl)).Returns(validationResult);
        _sqlDetectorMock.Setup(x => x.DetectAsync(It.IsAny<string>(), It.IsAny<HttpMethod>(), It.IsAny<AuthenticationResult>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<Vulnerability> { vulnerability });

        var vulnerabilityEvents = new List<VulnerabilityDetectedEventArgs>();
        _securityScanner.VulnerabilityDetected += (sender, args) => vulnerabilityEvents.Add(args);

        // Act
        await _securityScanner.ScanAsync(configuration);

        // Assert
        vulnerabilityEvents.Should().HaveCount(1);
        vulnerabilityEvents[0].Vulnerability.Should().Be(vulnerability);
        vulnerabilityEvents[0].Endpoint.Should().Be(targetUrl);
    }

    [Fact]
    public async Task ScanAsync_WithCancellation_ShouldCancelGracefully()
    {
        // Arrange
        var targetUrl = "http://localhost:3000";
        var configuration = new ScanConfiguration
        {
            TargetUrl = targetUrl,
            Depth = ScanDepth.Quick,
            VulnerabilityTypes = new List<VulnerabilityType> { VulnerabilityType.SqlInjection }
        };

        var validationResult = new UrlValidationResult
        {
            IsValid = true,
            IsLocalhost = true,
            ErrorMessage = null
        };

        var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromMilliseconds(100));

        _urlValidatorMock.Setup(x => x.Validate(targetUrl)).Returns(validationResult);
        _sqlDetectorMock.Setup(x => x.DetectAsync(It.IsAny<string>(), It.IsAny<HttpMethod>(), It.IsAny<AuthenticationResult>(), It.IsAny<CancellationToken>()))
            .Returns(async (string url, HttpMethod method, AuthenticationResult auth, CancellationToken ct) =>
            {
                await Task.Delay(1000, ct); // Simulate long-running operation
                return new List<Vulnerability>();
            });

        // Act
        var result = await _securityScanner.ScanAsync(configuration, cts.Token);

        // Assert
        result.Status.Should().Be(ScanStatus.Cancelled);
        result.EndTime.Should().NotBeNull();
    }

    [Fact]
    public async Task ScanAsync_WithMultipleEndpoints_ShouldTestAllEndpoints()
    {
        // Arrange
        var targetUrl = "http://localhost:3000";
        var configuration = new ScanConfiguration
        {
            TargetUrl = targetUrl,
            Depth = ScanDepth.Normal,
            VulnerabilityTypes = new List<VulnerabilityType> { VulnerabilityType.SqlInjection },
            IncludedPaths = new List<string> { "/api/users", "/api/products" },
            MaxConcurrentRequests = 2,
            MaxRequestsPerSecond = 10
        };

        var validationResult = new UrlValidationResult
        {
            IsValid = true,
            IsLocalhost = true,
            ErrorMessage = null
        };

        _urlValidatorMock.Setup(x => x.Validate(targetUrl)).Returns(validationResult);
        _sqlDetectorMock.Setup(x => x.DetectAsync(It.IsAny<string>(), It.IsAny<HttpMethod>(), It.IsAny<AuthenticationResult>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<Vulnerability>());

        // Act
        var result = await _securityScanner.ScanAsync(configuration);

        // Assert
        result.Should().NotBeNull();
        result.TestedEndpoints.Should().Contain(endpoint => endpoint.Contains("/api/users"));
        result.TestedEndpoints.Should().Contain(endpoint => endpoint.Contains("/api/products"));
        result.TestedEndpoints.Count.Should().BeGreaterThan(2); // Should include common endpoints too
    }
}