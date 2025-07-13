using Microsoft.Extensions.Logging;
using System.Net;

namespace VaultScope.Infrastructure.Exceptions;

public class GlobalExceptionHandler
{
    private readonly ILogger<GlobalExceptionHandler> _logger;

    public GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger)
    {
        _logger = logger;
    }

    public void HandleException(Exception exception, string context = "")
    {
        var correlationId = Guid.NewGuid().ToString();
        
        _logger.LogError(exception, 
            "[{CorrelationId}] Unhandled exception in {Context}: {Message}", 
            correlationId, context, exception.Message);

        switch (exception)
        {
            case UnauthorizedAccessException:
                _logger.LogWarning("[{CorrelationId}] Unauthorized access attempt: {Message}", 
                    correlationId, exception.Message);
                break;
                
            case TimeoutException:
                _logger.LogWarning("[{CorrelationId}] Operation timeout: {Message}", 
                    correlationId, exception.Message);
                break;
                
            case HttpRequestException httpEx:
                _logger.LogError("[{CorrelationId}] HTTP request failed: {Message}", 
                    correlationId, httpEx.Message);
                break;
                
            case ArgumentException argEx:
                _logger.LogWarning("[{CorrelationId}] Invalid argument: {ParameterName} - {Message}", 
                    correlationId, argEx.ParamName, argEx.Message);
                break;
                
            case InvalidOperationException:
                _logger.LogError("[{CorrelationId}] Invalid operation: {Message}", 
                    correlationId, exception.Message);
                break;
                
            case SecurityException secEx:
                _logger.LogCritical("[{CorrelationId}] Security violation detected: {Message}", 
                    correlationId, secEx.Message);
                break;
                
            default:
                _logger.LogCritical("[{CorrelationId}] Unexpected error of type {ExceptionType}: {Message}", 
                    correlationId, exception.GetType().Name, exception.Message);
                break;
        }
        
        // Log stack trace for critical errors
        if (exception is SecurityException || exception.InnerException != null)
        {
            _logger.LogDebug("[{CorrelationId}] Stack trace: {StackTrace}", 
                correlationId, exception.StackTrace);
        }
    }

    public async Task HandleExceptionAsync(Exception exception, string context = "")
    {
        await Task.Run(() => HandleException(exception, context));
    }
}

public class SecurityException : Exception
{
    public SecurityException(string message) : base(message) { }
    public SecurityException(string message, Exception innerException) : base(message, innerException) { }
}

public class ValidationException : Exception
{
    public string? FieldName { get; }
    
    public ValidationException(string message) : base(message) { }
    public ValidationException(string message, string fieldName) : base(message) 
    {
        FieldName = fieldName;
    }
    public ValidationException(string message, Exception innerException) : base(message, innerException) { }
}

public class ScanException : Exception
{
    public string? TargetUrl { get; }
    public string? ScanType { get; }
    
    public ScanException(string message) : base(message) { }
    public ScanException(string message, string targetUrl, string scanType) : base(message)
    {
        TargetUrl = targetUrl;
        ScanType = scanType;
    }
    public ScanException(string message, Exception innerException) : base(message, innerException) { }
}