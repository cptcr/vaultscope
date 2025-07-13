using Serilog;
using Serilog.Events;
using Serilog.Formatting.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace VaultScope.Infrastructure.Logging;

public static class SerilogConfiguration
{
    public static void ConfigureLogging(IConfiguration configuration, IHostEnvironment environment)
    {
        var loggerConfig = new LoggerConfiguration()
            .MinimumLevel.Information()
            .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
            .MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information)
            .MinimumLevel.Override("System", LogEventLevel.Warning)
            .MinimumLevel.Override("Microsoft.AspNetCore.Authentication", LogEventLevel.Information)
            .Enrich.FromLogContext()
            .Enrich.WithProcessId()
            .Enrich.WithThreadId()
            .Enrich.WithEnvironmentName()
            .Enrich.WithMachineName()
            .Enrich.WithProperty("Application", "VaultScope")
            .Enrich.WithProperty("Version", GetApplicationVersion());

        // Configure different sinks based on environment
        if (environment.IsDevelopment())
        {
            loggerConfig
                .MinimumLevel.Debug()
                .WriteTo.Console(
                    outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}")
                .WriteTo.File(
                    path: "logs/vaultscope-dev-.log",
                    rollingInterval: RollingInterval.Day,
                    retainedFileCountLimit: 7,
                    outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} {Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}");
        }
        else
        {
            // Production logging
            loggerConfig
                .WriteTo.Console(new JsonFormatter())
                .WriteTo.File(
                    new JsonFormatter(),
                    path: "logs/vaultscope-.log",
                    rollingInterval: RollingInterval.Day,
                    retainedFileCountLimit: 30,
                    fileSizeLimitBytes: 100 * 1024 * 1024, // 100MB
                    rollOnFileSizeLimit: true)
                .WriteTo.File(
                    path: "logs/errors/vaultscope-errors-.log",
                    restrictedToMinimumLevel: LogEventLevel.Error,
                    rollingInterval: RollingInterval.Day,
                    retainedFileCountLimit: 90,
                    outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} {Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}");
        }

        // Add security audit logging
        loggerConfig.WriteTo.Logger(securityLogger => securityLogger
            .Filter.ByIncludingOnly(evt => 
                evt.Properties.ContainsKey("SecurityEvent") ||
                evt.Level >= LogEventLevel.Warning)
            .WriteTo.File(
                path: "logs/security/security-audit-.log",
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 365, // Keep security logs for a year
                outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} {Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}"));

        // Configure Seq logging if endpoint is provided
        var seqServerUrl = configuration["Serilog:SeqServerUrl"];
        if (!string.IsNullOrEmpty(seqServerUrl))
        {
            loggerConfig.WriteTo.Seq(seqServerUrl);
        }

        Log.Logger = loggerConfig.CreateLogger();
    }

    private static string GetApplicationVersion()
    {
        try
        {
            var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
            return version?.ToString() ?? "unknown";
        }
        catch
        {
            return "unknown";
        }
    }
}

public static class SecurityLogging
{
    public static void LogSecurityEvent(string eventType, string message, object? data = null)
    {
        Log.Information("[SECURITY] {EventType}: {Message} {@Data}", eventType, message, data);
    }

    public static void LogAuthenticationAttempt(string username, bool success, string? ipAddress = null)
    {
        Log.Information("[SECURITY] Authentication {Result} for user {Username} from {IpAddress}", 
            success ? "SUCCESS" : "FAILURE", username, ipAddress ?? "unknown");
    }

    public static void LogScanAttempt(string targetUrl, string scanType, bool success, string? errorMessage = null)
    {
        if (success)
        {
            Log.Information("[SECURITY] Scan {ScanType} completed successfully for {TargetUrl}", 
                scanType, targetUrl);
        }
        else
        {
            Log.Warning("[SECURITY] Scan {ScanType} failed for {TargetUrl}: {ErrorMessage}", 
                scanType, targetUrl, errorMessage);
        }
    }

    public static void LogVulnerabilityFound(string vulnerabilityType, string severity, string targetUrl, string endpoint)
    {
        Log.Warning("[SECURITY] Vulnerability {VulnerabilityType} ({Severity}) found at {TargetUrl}{Endpoint}", 
            vulnerabilityType, severity, targetUrl, endpoint);
    }

    public static void LogSuspiciousActivity(string activityType, string details, string? source = null)
    {
        Log.Warning("[SECURITY] Suspicious activity detected: {ActivityType} - {Details} from {Source}", 
            activityType, details, source ?? "unknown");
    }

    public static void LogConfigurationChange(string setting, string? oldValue, string? newValue, string? changedBy = null)
    {
        Log.Information("[SECURITY] Configuration changed: {Setting} from '{OldValue}' to '{NewValue}' by {ChangedBy}", 
            setting, oldValue, newValue, changedBy ?? "system");
    }
}