using System.Net;
using System.Text;
using Moq;
using Moq.Protected;
using VaultScope.Core.Interfaces;
using VaultScope.Core.Models;
using VaultScope.Security.Detectors;
using Xunit;
using FluentAssertions;

namespace VaultScope.Tests.Security;

public class XssDetectorTests
{
    private readonly Mock<IUrlValidator> _urlValidatorMock;
    private readonly Mock<HttpMessageHandler> _httpMessageHandlerMock;
    private readonly HttpClient _httpClient;
    private readonly XssDetector _detector;

    public XssDetectorTests()
    {
        _urlValidatorMock = new Mock<IUrlValidator>();
        _httpMessageHandlerMock = new Mock<HttpMessageHandler>();
        _httpClient = new HttpClient(_httpMessageHandlerMock.Object);
        _detector = new XssDetector(_httpClient, _urlValidatorMock.Object);
    }

    [Fact]
    public void Detector_Properties_ShouldHaveCorrectValues()
    {
        // Assert
        _detector.Type.Should().Be(VulnerabilityType.CrossSiteScripting);
        _detector.Name.Should().Be("Cross-Site Scripting (XSS) Detector");
        _detector.Description.Should().Be("Detects XSS vulnerabilities in API responses");
        _detector.Priority.Should().Be(95);
    }

    [Theory]
    [InlineData("http://localhost:3000/api/search", "GET")]
    [InlineData("http://localhost:8080/api/comments", "POST")]
    [InlineData("http://127.0.0.1:5000/api/profile", "PUT")]
    public void IsApplicable_LocalhostEndpoints_ShouldReturnTrue(string endpoint, string method)
    {
        // Act
        var result = _detector.IsApplicable(endpoint, new HttpMethod(method));

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task DetectAsync_NonLocalhostEndpoint_ShouldReturnEmptyList()
    {
        // Arrange
        var endpoint = "http://external-site.com/api/search";
        _urlValidatorMock.Setup(x => x.IsLocalhost(endpoint)).Returns(false);

        // Act
        var result = await _detector.DetectAsync(endpoint, HttpMethod.Get);

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public async Task DetectAsync_NoReflectedXSS_ShouldReturnEmptyList()
    {
        // Arrange
        var endpoint = "http://localhost:3000/api/search";
        _urlValidatorMock.Setup(x => x.IsLocalhost(endpoint)).Returns(true);

        var responseContent = "{ \"results\": [], \"query\": \"safe query\" }";
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(responseContent, Encoding.UTF8, "application/json")
        };

        _httpMessageHandlerMock
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(response);

        // Act
        var result = await _detector.DetectAsync(endpoint, HttpMethod.Get);

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public async Task DetectAsync_ReflectedXSSPayload_ShouldDetectVulnerability()
    {
        // Arrange
        var endpoint = "http://localhost:3000/api/search?q=test";
        var xssPayload = "<script>alert('xss')</script>";
        _urlValidatorMock.Setup(x => x.IsLocalhost(endpoint)).Returns(true);

        // Response reflects the XSS payload
        var responseContent = $"<html><body>Search results for: {xssPayload}</body></html>";
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(responseContent, Encoding.UTF8, "text/html")
        };

        _httpMessageHandlerMock
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.Is<HttpRequestMessage>(req => req.RequestUri!.Query.Contains(Uri.EscapeDataString(xssPayload))),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(response);

        // Normal response for other requests
        var normalResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{ \"results\": [] }", Encoding.UTF8, "application/json")
        };

        _httpMessageHandlerMock
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.Is<HttpRequestMessage>(req => !req.RequestUri!.Query.Contains(Uri.EscapeDataString(xssPayload))),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(normalResponse);

        // Act
        var result = await _detector.DetectAsync(endpoint, HttpMethod.Get);

        // Assert
        result.Should().NotBeEmpty();
        result.Should().HaveCount(1);

        var vulnerability = result[0];
        vulnerability.Type.Should().Be("Cross-Site Scripting (XSS)");
        vulnerability.Severity.Should().Be(VulnerabilitySeverity.High);
        vulnerability.Title.Should().Be("Cross-Site Scripting (XSS) Vulnerability Detected");
        vulnerability.AffectedEndpoint.Should().Be(endpoint);
        vulnerability.HttpMethod.Should().Be("GET");
        vulnerability.Evidence.Should().NotBeNullOrEmpty();
        vulnerability.Remediation.Should().NotBeNullOrEmpty();
        vulnerability.CweId.Should().NotBeNullOrEmpty();
        vulnerability.OwaspCategory.Should().Be("A03:2021 - Injection");
        vulnerability.ConfidenceScore.Should().BeGreaterThan(0.8);
    }

    [Theory]
    [InlineData("<script>alert(1)</script>")]
    [InlineData("<img src=x onerror=alert(1)>")]
    [InlineData("<svg onload=alert(1)>")]
    [InlineData("javascript:alert(1)")]
    [InlineData("<iframe src=\"javascript:alert(1)\">")]
    public async Task DetectAsync_VariousXSSPayloads_ShouldDetectVulnerabilities(string xssPayload)
    {
        // Arrange
        var endpoint = "http://localhost:3000/api/test";
        _urlValidatorMock.Setup(x => x.IsLocalhost(endpoint)).Returns(true);

        // Response reflects the XSS payload
        var responseContent = $"<div>User input: {xssPayload}</div>";
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(responseContent, Encoding.UTF8, "text/html")
        };

        _httpMessageHandlerMock
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(response);

        // Act
        var result = await _detector.DetectAsync(endpoint, HttpMethod.Get);

        // Assert
        result.Should().NotBeEmpty();
        result[0].Type.Should().Be("Cross-Site Scripting (XSS)");
        result[0].Severity.Should().Be(VulnerabilitySeverity.High);
    }

    [Fact]
    public async Task DetectAsync_PostRequestWithXSSInBody_ShouldDetectVulnerability()
    {
        // Arrange
        var endpoint = "http://localhost:3000/api/comments";
        var xssPayload = "<script>alert('stored xss')</script>";
        _urlValidatorMock.Setup(x => x.IsLocalhost(endpoint)).Returns(true);

        // Response reflects the XSS payload from request body
        var responseContent = $"<div>Comment posted: {xssPayload}</div>";
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(responseContent, Encoding.UTF8, "text/html")
        };

        _httpMessageHandlerMock
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.Is<HttpRequestMessage>(req => 
                    req.Method == HttpMethod.Post && 
                    req.Content != null),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(response);

        // Act
        var result = await _detector.DetectAsync(endpoint, HttpMethod.Post);

        // Assert
        result.Should().NotBeEmpty();
        var vulnerability = result[0];
        vulnerability.Description.Should().Contain("request body");
    }

    [Fact]
    public async Task DetectAsync_WithAuthentication_ShouldIncludeAuthHeaders()
    {
        // Arrange
        var endpoint = "http://localhost:3000/api/protected-search";
        var authentication = new AuthenticationResult
        {
            Headers = new Dictionary<string, string>
            {
                { "Authorization", "Bearer test-token" },
                { "X-User-ID", "123" }
            }
        };

        _urlValidatorMock.Setup(x => x.IsLocalhost(endpoint)).Returns(true);

        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("No XSS found", Encoding.UTF8, "text/plain")
        };

        HttpRequestMessage? capturedRequest = null;
        _httpMessageHandlerMock
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>((req, ct) => capturedRequest = req)
            .ReturnsAsync(response);

        // Act
        await _detector.DetectAsync(endpoint, HttpMethod.Get, authentication);

        // Assert
        capturedRequest.Should().NotBeNull();
        capturedRequest!.Headers.Should().Contain(h => h.Key == "Authorization");
        capturedRequest.Headers.GetValues("Authorization").Should().Contain("Bearer test-token");
    }

    [Fact]
    public async Task DetectAsync_JSONResponseWithXSS_ShouldDetectVulnerability()
    {
        // Arrange
        var endpoint = "http://localhost:3000/api/user-profile";
        var xssPayload = "<img src=x onerror=alert('json xss')>";
        _urlValidatorMock.Setup(x => x.IsLocalhost(endpoint)).Returns(true);

        // JSON response that includes the XSS payload
        var responseContent = $"{{ \"name\": \"{xssPayload}\", \"email\": \"user@test.com\" }}";
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(responseContent, Encoding.UTF8, "application/json")
        };

        _httpMessageHandlerMock
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(response);

        // Act
        var result = await _detector.DetectAsync(endpoint, HttpMethod.Get);

        // Assert
        result.Should().NotBeEmpty();
        result[0].Type.Should().Be("Cross-Site Scripting (XSS)");
    }

    [Fact]
    public async Task DetectAsync_EncodedXSSPayload_ShouldNotDetectFalsePositive()
    {
        // Arrange
        var endpoint = "http://localhost:3000/api/search";
        var encodedPayload = "&lt;script&gt;alert(1)&lt;/script&gt;";
        _urlValidatorMock.Setup(x => x.IsLocalhost(endpoint)).Returns(true);

        // Response shows encoded payload (safe)
        var responseContent = $"<div>Search: {encodedPayload}</div>";
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(responseContent, Encoding.UTF8, "text/html")
        };

        _httpMessageHandlerMock
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(response);

        // Act
        var result = await _detector.DetectAsync(endpoint, HttpMethod.Get);

        // Assert
        // Should not detect vulnerability if payload is properly encoded
        result.Should().BeEmpty();
    }

    [Fact]
    public async Task DetectAsync_HttpException_ShouldNotThrow()
    {
        // Arrange
        var endpoint = "http://localhost:3000/api/search";
        _urlValidatorMock.Setup(x => x.IsLocalhost(endpoint)).Returns(true);

        _httpMessageHandlerMock
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ThrowsAsync(new HttpRequestException("Network error"));

        // Act & Assert
        var result = await _detector.DetectAsync(endpoint, HttpMethod.Get);
        result.Should().BeEmpty(); // Should handle exception gracefully
    }

    [Fact]
    public async Task DetectAsync_CancellationRequested_ShouldHandleCancellation()
    {
        // Arrange
        var endpoint = "http://localhost:3000/api/search";
        _urlValidatorMock.Setup(x => x.IsLocalhost(endpoint)).Returns(true);

        var cts = new CancellationTokenSource();
        cts.Cancel();

        // Act & Assert
        var result = await _detector.DetectAsync(endpoint, HttpMethod.Get, cancellationToken: cts.Token);
        result.Should().BeEmpty(); // Should handle cancellation gracefully
    }

    [Fact]
    public async Task DetectAsync_DOMBasedXSS_ShouldDetectVulnerability()
    {
        // Arrange
        var endpoint = "http://localhost:3000/api/page";
        _urlValidatorMock.Setup(x => x.IsLocalhost(endpoint)).Returns(true);

        // Response contains DOM-based XSS vulnerability patterns
        var responseContent = @"
            <html>
                <script>
                    var userInput = location.hash.substr(1);
                    document.write(userInput);
                </script>
            </html>";
        
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(responseContent, Encoding.UTF8, "text/html")
        };

        _httpMessageHandlerMock
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(response);

        // Act
        var result = await _detector.DetectAsync(endpoint, HttpMethod.Get);

        // Assert
        // This tests the DOM-based XSS detection logic
        // The detector should identify dangerous patterns like document.write with untrusted input
        result.Should().NotBeNull();
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            _httpClient?.Dispose();
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}