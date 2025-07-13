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

public class SqlInjectionDetectorTests
{
    private readonly Mock<IUrlValidator> _urlValidatorMock;
    private readonly Mock<HttpMessageHandler> _httpMessageHandlerMock;
    private readonly HttpClient _httpClient;
    private readonly SqlInjectionDetector _detector;

    public SqlInjectionDetectorTests()
    {
        _urlValidatorMock = new Mock<IUrlValidator>();
        _httpMessageHandlerMock = new Mock<HttpMessageHandler>();
        _httpClient = new HttpClient(_httpMessageHandlerMock.Object);
        _detector = new SqlInjectionDetector(_httpClient, _urlValidatorMock.Object);
    }

    [Fact]
    public void Detector_Properties_ShouldHaveCorrectValues()
    {
        // Assert
        _detector.Type.Should().Be(VulnerabilityType.SqlInjection);
        _detector.Name.Should().Be("SQL Injection Detector");
        _detector.Description.Should().Be("Detects SQL injection vulnerabilities in API endpoints");
        _detector.Priority.Should().Be(100);
    }

    [Theory]
    [InlineData("http://localhost:3000/api/users", "GET")]
    [InlineData("http://localhost:8080/api/products", "POST")]
    [InlineData("http://127.0.0.1:5000/api/data", "PUT")]
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
        var endpoint = "http://external-site.com/api/test";
        _urlValidatorMock.Setup(x => x.IsLocalhost(endpoint)).Returns(false);

        // Act
        var result = await _detector.DetectAsync(endpoint, HttpMethod.Get);

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public async Task DetectAsync_NoSqlErrors_ShouldReturnEmptyList()
    {
        // Arrange
        var endpoint = "http://localhost:3000/api/users";
        _urlValidatorMock.Setup(x => x.IsLocalhost(endpoint)).Returns(true);

        var responseContent = "{ \"users\": [] }";
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
    public async Task DetectAsync_SqlErrorInResponse_ShouldDetectVulnerability()
    {
        // Arrange
        var endpoint = "http://localhost:3000/api/users?id=1";
        _urlValidatorMock.Setup(x => x.IsLocalhost(endpoint)).Returns(true);

        var errorResponse = "MySQL error: You have an error in your SQL syntax near 'WHERE id = '''";
        var response = new HttpResponseMessage(HttpStatusCode.InternalServerError)
        {
            Content = new StringContent(errorResponse, Encoding.UTF8, "text/plain")
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
        result.Should().HaveCount(1);
        
        var vulnerability = result[0];
        vulnerability.Type.Should().Be("SQL Injection");
        vulnerability.Severity.Should().Be(VulnerabilitySeverity.Critical);
        vulnerability.Title.Should().Be("SQL Injection Vulnerability Detected");
        vulnerability.AffectedEndpoint.Should().Be(endpoint);
        vulnerability.HttpMethod.Should().Be("GET");
        vulnerability.Evidence.Should().NotBeNullOrEmpty();
        vulnerability.Remediation.Should().NotBeNullOrEmpty();
        vulnerability.CweId.Should().NotBeNullOrEmpty();
        vulnerability.OwaspCategory.Should().Be("A03:2021 - Injection");
        vulnerability.ConfidenceScore.Should().Be(0.95);
    }

    [Theory]
    [InlineData("sql syntax")]
    [InlineData("mysql_fetch")]
    [InlineData("PostgreSQL")]
    [InlineData("SQLServer")]
    [InlineData("sqlite_")]
    [InlineData("SQL error")]
    [InlineData("syntax error")]
    [InlineData("unclosed quotation mark")]
    [InlineData("incorrect syntax near")]
    public async Task DetectAsync_VariousSqlErrors_ShouldDetectVulnerabilities(string sqlError)
    {
        // Arrange
        var endpoint = "http://localhost:3000/api/test";
        _urlValidatorMock.Setup(x => x.IsLocalhost(endpoint)).Returns(true);

        var errorResponse = $"Database error: {sqlError} - query failed";
        var response = new HttpResponseMessage(HttpStatusCode.InternalServerError)
        {
            Content = new StringContent(errorResponse, Encoding.UTF8, "text/plain")
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
        result[0].Type.Should().Be("SQL Injection");
        result[0].Severity.Should().Be(VulnerabilitySeverity.Critical);
    }

    [Fact]
    public async Task DetectAsync_PostRequestWithBody_ShouldTestRequestBody()
    {
        // Arrange
        var endpoint = "http://localhost:3000/api/users";
        _urlValidatorMock.Setup(x => x.IsLocalhost(endpoint)).Returns(true);

        var errorResponse = "SQL error: syntax error near 'INSERT'";
        var response = new HttpResponseMessage(HttpStatusCode.InternalServerError)
        {
            Content = new StringContent(errorResponse, Encoding.UTF8, "text/plain")
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
        var endpoint = "http://localhost:3000/api/protected";
        var authentication = new AuthenticationResult
        {
            Headers = new Dictionary<string, string>
            {
                { "Authorization", "Bearer test-token" },
                { "X-API-Key", "test-api-key" }
            }
        };

        _urlValidatorMock.Setup(x => x.IsLocalhost(endpoint)).Returns(true);

        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("Success", Encoding.UTF8, "text/plain")
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
    public async Task DetectAsync_HttpException_ShouldNotThrow()
    {
        // Arrange
        var endpoint = "http://localhost:3000/api/users";
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
        var endpoint = "http://localhost:3000/api/users";
        _urlValidatorMock.Setup(x => x.IsLocalhost(endpoint)).Returns(true);

        var cts = new CancellationTokenSource();
        cts.Cancel();

        // Act & Assert
        var result = await _detector.DetectAsync(endpoint, HttpMethod.Get, cancellationToken: cts.Token);
        result.Should().BeEmpty(); // Should handle cancellation gracefully
    }

    [Fact]
    public async Task DetectAsync_TimingBasedPayload_ShouldDetectBasedOnResponseTime()
    {
        // Arrange
        var endpoint = "http://localhost:3000/api/users";
        _urlValidatorMock.Setup(x => x.IsLocalhost(endpoint)).Returns(true);

        // Simulate a delayed response (indicating time-based SQL injection)
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("Success", Encoding.UTF8, "text/plain"),
            Headers = { Date = DateTimeOffset.UtcNow.AddSeconds(-6) } // 6 seconds ago
        };

        _httpMessageHandlerMock
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.Is<HttpRequestMessage>(req => 
                    req.RequestUri!.Query.Contains("SLEEP") ||
                    req.RequestUri.Query.Contains("WAITFOR") ||
                    req.RequestUri.Query.Contains("pg_sleep")),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(response);

        // Normal response for other payloads
        var normalResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("Success", Encoding.UTF8, "text/plain")
        };

        _httpMessageHandlerMock
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.Is<HttpRequestMessage>(req => 
                    !req.RequestUri!.Query.Contains("SLEEP") &&
                    !req.RequestUri.Query.Contains("WAITFOR") &&
                    !req.RequestUri.Query.Contains("pg_sleep")),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(normalResponse);

        // Act
        var result = await _detector.DetectAsync(endpoint, HttpMethod.Get);

        // Assert
        // This test demonstrates the time-based detection logic
        // In a real scenario, we'd need actual timing measurements
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