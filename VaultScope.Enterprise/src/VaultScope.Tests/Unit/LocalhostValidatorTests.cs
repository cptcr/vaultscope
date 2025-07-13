using Xunit;
using FluentAssertions;
using VaultScope.Security.Validators;

namespace VaultScope.Tests.Unit;

public class LocalhostValidatorTests
{
    private readonly LocalhostValidator _validator;

    public LocalhostValidatorTests()
    {
        _validator = new LocalhostValidator();
    }

    [Theory]
    [InlineData("http://localhost")]
    [InlineData("https://localhost")]
    [InlineData("http://127.0.0.1")]
    [InlineData("https://127.0.0.1")]
    [InlineData("http://[::1]")]
    [InlineData("https://[::1]")]
    [InlineData("http://test.localhost")]
    [InlineData("https://app.local")]
    public void Validate_ValidLocalhostUrls_ReturnsSuccess(string url)
    {
        // Act
        var result = _validator.Validate(url);

        // Assert
        result.IsValid.Should().BeTrue();
        result.IsLocalhost.Should().BeTrue();
        result.ErrorMessage.Should().BeNull();
        result.ParsedUri.Should().NotBeNull();
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_EmptyOrWhitespaceUrl_ReturnsFailure(string url)
    {
        // Act
        var result = _validator.Validate(url);

        // Assert
        result.IsValid.Should().BeFalse();
        result.ErrorMessage.Should().Be("URL cannot be empty");
    }

    [Fact]
    public void Validate_NullUrl_ReturnsFailure()
    {
        // Act
        var result = _validator.Validate(null!);

        // Assert
        result.IsValid.Should().BeFalse();
        result.ErrorMessage.Should().Be("URL cannot be empty");
    }

    [Theory]
    [InlineData("ftp://localhost")]
    [InlineData("file://localhost")]
    [InlineData("javascript:alert('xss')")]
    [InlineData("data:text/html,<script>alert('xss')</script>")]
    public void Validate_UnsupportedSchemes_ReturnsFailure(string url)
    {
        // Act
        var result = _validator.Validate(url);

        // Assert
        result.IsValid.Should().BeFalse();
        result.ErrorMessage.Should().Contain("Unsupported scheme");
    }

    [Theory]
    [InlineData("http://localhost:22")]    // SSH
    [InlineData("http://localhost:3389")]  // RDP
    [InlineData("http://localhost:1433")]  // SQL Server
    [InlineData("http://localhost:5432")]  // PostgreSQL
    public void Validate_DangerousPorts_ReturnsFailure(string url)
    {
        // Act
        var result = _validator.Validate(url);

        // Assert
        result.IsValid.Should().BeFalse();
        result.ErrorMessage.Should().Contain("not allowed for security reasons");
    }

    [Theory]
    [InlineData("http://localhost/../../../etc/passwd")]
    [InlineData("http://localhost/test?file=../../../etc/passwd")]
    [InlineData("http://localhost/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd")]
    [InlineData("javascript:alert('xss')")]
    [InlineData("data:text/html,<script>")]
    public void Validate_SuspiciousPatterns_ReturnsFailure(string url)
    {
        // Act
        var result = _validator.Validate(url);

        // Assert
        result.IsValid.Should().BeFalse();
        result.ErrorMessage.Should().Contain("suspicious patterns");
    }

    [Fact]
    public void Validate_TooLongUrl_ReturnsFailure()
    {
        // Arrange
        var longUrl = "http://localhost/" + new string('a', 2050);

        // Act
        var result = _validator.Validate(longUrl);

        // Assert
        result.IsValid.Should().BeFalse();
        result.ErrorMessage.Should().Contain("too long");
    }

    [Theory]
    [InlineData("http://user:pass@localhost")]
    [InlineData("https://admin:secret@127.0.0.1")]
    public void Validate_UrlsWithUserInfo_ReturnsFailure(string url)
    {
        // Act
        var result = _validator.Validate(url);

        // Assert
        result.IsValid.Should().BeFalse();
        result.ErrorMessage.Should().Contain("user information are not allowed");
    }

    [Theory]
    [InlineData("http://google.com")]
    [InlineData("https://example.com")]
    [InlineData("http://192.168.1.1")]
    [InlineData("https://10.0.0.1")]
    public void Validate_NonLocalhostUrls_ReturnsFailure(string url)
    {
        // Act
        var result = _validator.Validate(url);

        // Assert
        result.IsValid.Should().BeFalse();
        result.ErrorMessage.Should().Contain("Only localhost URLs are allowed");
    }

    [Theory]
    [InlineData("http://localhost:8080")]
    [InlineData("https://localhost:443")]
    [InlineData("http://127.0.0.1:3000")]
    [InlineData("https://[::1]:8443")]
    public void Validate_ValidPortNumbers_ReturnsSuccess(string url)
    {
        // Act
        var result = _validator.Validate(url);

        // Assert
        result.IsValid.Should().BeTrue();
        result.IsLocalhost.Should().BeTrue();
    }

    [Theory]
    [InlineData("http://localhost:0")]
    [InlineData("http://localhost:65536")]
    [InlineData("http://localhost:99999")]
    public void Validate_InvalidPortNumbers_ReturnsFailure(string url)
    {
        // Act
        var result = _validator.Validate(url);

        // Assert
        result.IsValid.Should().BeFalse();
        result.ErrorMessage.Should().Contain("Invalid port number");
    }

    [Fact]
    public void IsValid_ValidUrl_ReturnsTrue()
    {
        // Arrange
        var url = "https://localhost:8080";

        // Act
        var result = _validator.IsValid(url);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void IsLocalhost_LocalhostUrl_ReturnsTrue()
    {
        // Arrange
        var url = "https://localhost:8080";

        // Act
        var result = _validator.IsLocalhost(url);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void IsLocalhost_NonLocalhostUrl_ReturnsFalse()
    {
        // Arrange
        var url = "https://example.com";

        // Act
        var result = _validator.IsLocalhost(url);

        // Assert
        result.Should().BeFalse();
    }
}