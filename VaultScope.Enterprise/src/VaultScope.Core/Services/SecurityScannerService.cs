using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using VaultScope.Core.Interfaces;
using VaultScope.Core.Models;

namespace VaultScope.Core.Services;

public class SecurityScannerService : ISecurityScanner
{
    private readonly IEnumerable<IVulnerabilityDetector> _vulnerabilityDetectors;
    private readonly IUrlValidator _urlValidator;
    private readonly ILogger<SecurityScannerService> _logger;
    private readonly SecurityScoreCalculator _scoreCalculator;
    
    public event EventHandler<ScanProgressEventArgs>? ProgressChanged;
    public event EventHandler<VulnerabilityDetectedEventArgs>? VulnerabilityDetected;
    
    public SecurityScannerService(
        IEnumerable<IVulnerabilityDetector> vulnerabilityDetectors,
        IUrlValidator urlValidator,
        ILogger<SecurityScannerService> logger,
        SecurityScoreCalculator scoreCalculator)
    {
        _vulnerabilityDetectors = vulnerabilityDetectors;
        _urlValidator = urlValidator;
        _logger = logger;
        _scoreCalculator = scoreCalculator;
    }
    
    public async Task<ScanResult> ScanAsync(ScanConfiguration configuration, CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Starting security scan for {Url}", configuration.TargetUrl);
        
        var validationResult = _urlValidator.Validate(configuration.TargetUrl);
        if (!validationResult.IsValid || !validationResult.IsLocalhost)
        {
            throw new ArgumentException($"Invalid URL: {validationResult.ErrorMessage}");
        }
        
        var scanResult = new ScanResult
        {
            TargetUrl = configuration.TargetUrl,
            StartTime = DateTime.UtcNow,
            Status = ScanStatus.InProgress
        };
        
        try
        {
            await PerformScanAsync(scanResult, configuration, cancellationToken);
            
            scanResult.Status = ScanStatus.Completed;
            scanResult.EndTime = DateTime.UtcNow;
            
            // Calculate security score
            scanResult.SecurityScore = _scoreCalculator.Calculate(scanResult);
            
            _logger.LogInformation("Security scan completed. Found {Count} vulnerabilities", 
                scanResult.Vulnerabilities.Count);
        }
        catch (OperationCanceledException)
        {
            scanResult.Status = ScanStatus.Cancelled;
            scanResult.EndTime = DateTime.UtcNow;
            _logger.LogWarning("Security scan was cancelled");
        }
        catch (Exception ex)
        {
            scanResult.Status = ScanStatus.Failed;
            scanResult.EndTime = DateTime.UtcNow;
            scanResult.ErrorMessage = ex.Message;
            _logger.LogError(ex, "Security scan failed");
            throw;
        }
        
        return scanResult;
    }
    
    public async Task<ScanResult> QuickScanAsync(string targetUrl, CancellationToken cancellationToken = default)
    {
        var configuration = new ScanConfiguration
        {
            TargetUrl = targetUrl,
            Depth = ScanDepth.Quick,
            VulnerabilityTypes = new List<VulnerabilityType>
            {
                VulnerabilityType.SqlInjection,
                VulnerabilityType.CrossSiteScripting,
                VulnerabilityType.AuthenticationBypass,
                VulnerabilityType.MissingSecurityHeaders
            }
        };
        
        return await ScanAsync(configuration, cancellationToken);
    }
    
    private async Task PerformScanAsync(
        ScanResult scanResult,
        ScanConfiguration configuration,
        CancellationToken cancellationToken)
    {
        var endpoints = await DiscoverEndpointsAsync(configuration, cancellationToken);
        scanResult.TestedEndpoints = endpoints.Select(e => e.Url).ToList();
        
        var httpMethods = configuration.TestAllHttpMethods
            ? new[] { HttpMethod.Get, HttpMethod.Post, HttpMethod.Put, HttpMethod.Delete, new HttpMethod("PATCH") }
            : new[] { HttpMethod.Get };
        
        var totalTasks = endpoints.Count * httpMethods.Length * _vulnerabilityDetectors.Count();
        var completedTasks = 0;
        var startTime = DateTime.UtcNow;
        
        // Filter detectors based on configuration
        var activeDetectors = _vulnerabilityDetectors
            .Where(d => configuration.VulnerabilityTypes.Contains(d.Type))
            .OrderByDescending(d => d.Priority)
            .ToList();
        
        var vulnerabilities = new ConcurrentBag<Vulnerability>();
        var semaphore = new SemaphoreSlim(configuration.MaxConcurrentRequests);
        
        var tasks = new List<Task>();
        
        foreach (var endpoint in endpoints)
        {
            foreach (var method in httpMethods)
            {
                foreach (var detector in activeDetectors)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;
                    
                    if (!detector.IsApplicable(endpoint.Url, method))
                    {
                        completedTasks++;
                        continue;
                    }
                    
                    var task = Task.Run(async () =>
                    {
                        await semaphore.WaitAsync(cancellationToken);
                        try
                        {
                            _logger.LogDebug("Testing {Endpoint} with {Method} using {Detector}",
                                endpoint.Url, method, detector.Name);
                            
                            var detectedVulnerabilities = await detector.DetectAsync(
                                endpoint.Url,
                                method,
                                configuration.Authentication,
                                cancellationToken);
                            
                            foreach (var vulnerability in detectedVulnerabilities)
                            {
                                vulnerabilities.Add(vulnerability);
                                OnVulnerabilityDetected(vulnerability, endpoint.Url);
                            }
                            
                            Interlocked.Increment(ref completedTasks);
                            
                            // Update progress
                            var progress = (double)completedTasks / totalTasks * 100;
                            OnProgressChanged(new ScanProgressEventArgs
                            {
                                ProgressPercentage = progress,
                                CurrentTask = $"Testing {endpoint.Path} with {detector.Name}",
                                VulnerabilitiesFound = vulnerabilities.Count,
                                EndpointsTested = endpoints.Count,
                                ElapsedTime = DateTime.UtcNow - startTime
                            });
                        }
                        finally
                        {
                            semaphore.Release();
                        }
                        
                        // Rate limiting
                        await Task.Delay(1000 / configuration.MaxRequestsPerSecond, cancellationToken);
                    }, cancellationToken);
                    
                    tasks.Add(task);
                }
            }
        }
        
        await Task.WhenAll(tasks);
        
        scanResult.Vulnerabilities = vulnerabilities.ToList();
        scanResult.TotalRequestsMade = completedTasks;
        
        // Calculate vulnerability count by severity
        scanResult.VulnerabilityCountBySeverity = scanResult.Vulnerabilities
            .GroupBy(v => v.Severity)
            .ToDictionary(g => g.Key.ToString(), g => g.Count());
    }
    
    private async Task<List<Endpoint>> DiscoverEndpointsAsync(
        ScanConfiguration configuration,
        CancellationToken cancellationToken)
    {
        return await Task.Run(() =>
        {
            var endpoints = new List<Endpoint>();
            var baseUri = new Uri(configuration.TargetUrl);

            // Add base URL
            endpoints.Add(new Endpoint { Url = configuration.TargetUrl, Path = "/" });

            // Add configured paths
            foreach (var path in configuration.IncludedPaths)
            {
                if (configuration.ExcludedPaths.Contains(path))
                    continue;

                var url = new Uri(baseUri, path).ToString();
                endpoints.Add(new Endpoint { Url = url, Path = path });
            }

            // In a real implementation, you might:
            // - Crawl the API documentation
            // - Parse OpenAPI/Swagger specs
            // - Discover endpoints through OPTIONS requests
            // - Use wordlists for common API endpoints

            // For now, add common API endpoints
            if (configuration.Depth >= ScanDepth.Normal)
            {
                var commonEndpoints = new[]
                {
                    "/api", "/api/v1", "/api/v2",
                    "/api/users", "/api/login", "/api/auth",
                    "/api/admin", "/api/config", "/api/status",
                    "/api/health", "/api/version"
                };

                foreach (var endpoint in commonEndpoints)
                {
                    if (!configuration.ExcludedPaths.Contains(endpoint))
                    {
                        var url = new Uri(baseUri, endpoint).ToString();
                        endpoints.Add(new Endpoint { Url = url, Path = endpoint });
                    }
                }
            }

            return endpoints.Distinct().ToList();
        }, cancellationToken);
    }
    
    private void OnProgressChanged(ScanProgressEventArgs args)
    {
        ProgressChanged?.Invoke(this, args);
    }
    
    private void OnVulnerabilityDetected(Vulnerability vulnerability, string endpoint)
    {
        VulnerabilityDetected?.Invoke(this, new VulnerabilityDetectedEventArgs
        {
            Vulnerability = vulnerability,
            Endpoint = endpoint,
            DetectedAt = DateTime.UtcNow
        });
    }
    
    private class Endpoint : IEquatable<Endpoint>
    {
        public string Url { get; set; } = string.Empty;
        public string Path { get; set; } = string.Empty;
        
        public bool Equals(Endpoint? other)
        {
            return other != null && Url.Equals(other.Url, StringComparison.OrdinalIgnoreCase);
        }
        
        public override bool Equals(object? obj)
        {
            return Equals(obj as Endpoint);
        }
        
        public override int GetHashCode()
        {
            return Url.GetHashCode(StringComparison.OrdinalIgnoreCase);
        }
    }
}