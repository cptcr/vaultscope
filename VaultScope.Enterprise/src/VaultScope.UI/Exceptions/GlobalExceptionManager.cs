using Avalonia.Threading;
using Microsoft.Extensions.Logging;
using VaultScope.Infrastructure.Exceptions;
using System.Diagnostics;

namespace VaultScope.UI.Exceptions;

public class GlobalExceptionManager
{
    private readonly ILogger<GlobalExceptionManager> _logger;
    private readonly GlobalExceptionHandler _exceptionHandler;
    private bool _isHandlingException = false;

    public GlobalExceptionManager(ILogger<GlobalExceptionManager> logger, GlobalExceptionHandler exceptionHandler)
    {
        _logger = logger;
        _exceptionHandler = exceptionHandler;
        
        // Hook into application domain unhandled exceptions
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
        
        // Hook into task unhandled exceptions
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
        
        // Hook into dispatcher unhandled exceptions
        Dispatcher.UIThread.UnhandledException += OnDispatcherUnhandledException;
    }

    private void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is Exception exception)
        {
            HandleException(exception, "AppDomain.UnhandledException");
        }
    }

    private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        HandleException(e.Exception, "TaskScheduler.UnobservedTaskException");
        e.SetObserved(); // Prevent the process from terminating
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        HandleException(e.Exception, "Dispatcher.UnhandledException");
        e.Handled = true; // Prevent the application from crashing
    }

    private void HandleException(Exception exception, string context)
    {
        // Prevent recursive exception handling
        if (_isHandlingException)
        {
            return;
        }

        try
        {
            _isHandlingException = true;
            
            _exceptionHandler.HandleException(exception, context);
            
            // Show user-friendly error message
            _ = ShowUserErrorMessage(exception, context);
        }
        catch (Exception handlerException)
        {
            // Log to debug console as last resort
            Debug.WriteLine($"Exception handler failed: {handlerException}");
            
            // Try to write to event log or console
            try
            {
                Console.WriteLine($"Critical error: {exception}");
                Console.WriteLine($"Handler error: {handlerException}");
            }
            catch
            {
                // Silent fail - nowhere left to log
            }
        }
        finally
        {
            _isHandlingException = false;
        }
    }

    private async Task ShowUserErrorMessage(Exception exception, string context)
    {
        try
        {
            string userMessage = GetUserFriendlyMessage(exception);
            string title = "Application Error";
            
            // Only show critical errors to user to avoid spam
            if (ShouldShowToUser(exception))
            {
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    try
                    {
                        // Log the error for now - MessageBox can be implemented later
                        _logger.LogError("User notification: {Title} - {Message}", title, userMessage);
                        
                        // TODO: Implement proper user notification UI
                        // For now, we'll just log the error
                        Console.WriteLine($"ERROR: {title} - {userMessage}");
                    }
                    catch
                    {
                        // Fallback: just log that we couldn't show the message
                        _logger.LogWarning("Could not display error message to user");
                    }
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to show error message to user");
        }
    }

    private static string GetUserFriendlyMessage(Exception exception)
    {
        return exception switch
        {
            UnauthorizedAccessException => "Access denied. Please check your permissions.",
            TimeoutException => "The operation timed out. Please try again.",
            HttpRequestException => "Network error occurred. Please check your connection.",
            ValidationException valEx => $"Invalid input: {valEx.Message}",
            ScanException scanEx => $"Scan failed: {scanEx.Message}",
            SecurityException => "A security error occurred. Please contact support.",
            _ => "An unexpected error occurred. Please try again or contact support."
        };
    }

    private static bool ShouldShowToUser(Exception exception)
    {
        // Don't spam user with every exception
        return exception switch
        {
            UnauthorizedAccessException => true,
            ValidationException => true,
            ScanException => true,
            SecurityException => true,
            TimeoutException => true,
            HttpRequestException => true,
            _ => false // Log but don't show generic exceptions
        };
    }

    public void Dispose()
    {
        AppDomain.CurrentDomain.UnhandledException -= OnUnhandledException;
        TaskScheduler.UnobservedTaskException -= OnUnobservedTaskException;
        Dispatcher.UIThread.UnhandledException -= OnDispatcherUnhandledException;
    }
}