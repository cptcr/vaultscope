using Xunit;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using VaultScope.Infrastructure.Exceptions;
using System.Net;

namespace VaultScope.Tests.Unit;

public class GlobalExceptionHandlerTests
{
    private readonly Mock<ILogger<GlobalExceptionHandler>> _mockLogger;
    private readonly GlobalExceptionHandler _handler;

    public GlobalExceptionHandlerTests()
    {
        _mockLogger = new Mock<ILogger<GlobalExceptionHandler>>();
        _handler = new GlobalExceptionHandler(_mockLogger.Object);
    }

    [Fact]
    public void HandleException_GeneralException_LogsError()
    {
        // Arrange
        var exception = new Exception("Test exception");
        var context = "TestContext";

        // Act
        _handler.HandleException(exception, context);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Unhandled exception")),
                exception,
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public void HandleException_UnauthorizedAccessException_LogsWarning()
    {
        // Arrange
        var exception = new UnauthorizedAccessException("Access denied");
        var context = "TestContext";

        // Act
        _handler.HandleException(exception, context);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Unauthorized access attempt")),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public void HandleException_TimeoutException_LogsWarning()
    {
        // Arrange
        var exception = new TimeoutException("Operation timed out");
        var context = "TestContext";

        // Act
        _handler.HandleException(exception, context);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Operation timeout")),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public void HandleException_HttpRequestException_LogsError()
    {
        // Arrange
        var exception = new HttpRequestException("HTTP request failed");
        var context = "TestContext";

        // Act
        _handler.HandleException(exception, context);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("HTTP request failed")),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public void HandleException_ArgumentException_LogsWarning()
    {
        // Arrange
        var exception = new ArgumentException("Invalid argument", "paramName");
        var context = "TestContext";

        // Act
        _handler.HandleException(exception, context);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Invalid argument")),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public void HandleException_SecurityException_LogsCritical()
    {
        // Arrange
        var exception = new SecurityException("Security violation");
        var context = "TestContext";

        // Act
        _handler.HandleException(exception, context);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Critical,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Security violation detected")),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public void HandleException_InvalidOperationException_LogsError()
    {
        // Arrange
        var exception = new InvalidOperationException("Invalid operation");
        var context = "TestContext";

        // Act
        _handler.HandleException(exception, context);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Invalid operation")),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task HandleExceptionAsync_CallsHandleException()
    {
        // Arrange
        var exception = new Exception("Test exception");
        var context = "TestContext";

        // Act
        await _handler.HandleExceptionAsync(exception, context);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Unhandled exception")),
                exception,
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public void HandleException_IncludesCorrelationId()
    {
        // Arrange
        var exception = new Exception("Test exception");
        var context = "TestContext";

        // Act
        _handler.HandleException(exception, context);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("[")), // Correlation ID format
                exception,
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public void HandleException_WithInnerException_LogsStackTrace()
    {
        // Arrange
        var innerException = new Exception("Inner exception");
        var exception = new Exception("Outer exception", innerException);
        var context = "TestContext";

        // Act
        _handler.HandleException(exception, context);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Debug,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Stack trace")),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }
}

public class SecurityExceptionTests
{
    [Fact]
    public void SecurityException_WithMessage_SetsMessage()
    {
        // Arrange
        var message = "Security violation detected";

        // Act
        var exception = new SecurityException(message);

        // Assert
        exception.Message.Should().Be(message);
    }

    [Fact]
    public void SecurityException_WithMessageAndInnerException_SetsProperties()
    {
        // Arrange
        var message = "Security violation detected";
        var innerException = new Exception("Inner exception");

        // Act
        var exception = new SecurityException(message, innerException);

        // Assert
        exception.Message.Should().Be(message);
        exception.InnerException.Should().Be(innerException);
    }
}

public class ValidationExceptionTests
{
    [Fact]
    public void ValidationException_WithMessage_SetsMessage()
    {
        // Arrange
        var message = "Validation failed";

        // Act
        var exception = new ValidationException(message);

        // Assert
        exception.Message.Should().Be(message);
        exception.FieldName.Should().BeNull();
    }

    [Fact]
    public void ValidationException_WithMessageAndFieldName_SetsProperties()
    {
        // Arrange
        var message = "Invalid email format";
        var fieldName = "Email";

        // Act
        var exception = new ValidationException(message, fieldName);

        // Assert
        exception.Message.Should().Be(message);
        exception.FieldName.Should().Be(fieldName);
    }
}

public class ScanExceptionTests
{
    [Fact]
    public void ScanException_WithMessage_SetsMessage()
    {
        // Arrange
        var message = "Scan failed";

        // Act
        var exception = new ScanException(message);

        // Assert
        exception.Message.Should().Be(message);
        exception.TargetUrl.Should().BeNull();
        exception.ScanType.Should().BeNull();
    }

    [Fact]
    public void ScanException_WithAllParameters_SetsProperties()
    {
        // Arrange
        var message = "SQL injection scan failed";
        var targetUrl = "http://localhost:8080";
        var scanType = "SQLInjection";

        // Act
        var exception = new ScanException(message, targetUrl, scanType);

        // Assert
        exception.Message.Should().Be(message);
        exception.TargetUrl.Should().Be(targetUrl);
        exception.ScanType.Should().Be(scanType);
    }
}