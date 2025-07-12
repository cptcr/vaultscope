using System.Diagnostics;
using VaultScope.Core.Constants;
using VaultScope.Core.Interfaces;
using VaultScope.Core.Models;

namespace VaultScope.Security.Detectors;

public class RateLimitingDetector : IVulnerabilityDetector
{
    private readonly HttpClient _httpClient;
    private readonly IUrlValidator _urlValidator;
    
    public VulnerabilityType Type => VulnerabilityType.RateLimiting;
    public string Name => "Rate Limiting Detector";
    public string Description => "Detects missing or weak rate limiting on API endpoints";
    public int Priority => 70;
    
    public RateLimitingDetector(HttpClient httpClient, IUrlValidator urlValidator)
    {
        _httpClient = httpClient;
        _urlValidator = urlValidator;
    }
    
    public async Task<List<Vulnerability>> DetectAsync(
        string endpoint,
        HttpMethod method,
        AuthenticationResult? authentication = null,
        CancellationToken cancellationToken = default)
    {
        var vulnerabilities = new List<Vulnerability>();
        
        if (!_urlValidator.IsLocalhost(endpoint))
            return vulnerabilities;
        
        // Test different rate limiting scenarios
        var tests = new List<RateLimitTest>
        {
            await TestBasicRateLimit(endpoint, method, authentication, cancellationToken),
            await TestBurstRequests(endpoint, method, authentication, cancellationToken),
            await TestSlowRequests(endpoint, method, authentication, cancellationToken),
            await TestDifferentUserAgents(endpoint, method, authentication, cancellationToken),
            await TestDifferentIPs(endpoint, method, authentication, cancellationToken)
        };
        
        foreach (var test in tests.Where(t => t.IsVulnerable))
        {
            vulnerabilities.Add(CreateVulnerability(endpoint, method, test));
        }
        
        return vulnerabilities;
    }
    
    public bool IsApplicable(string endpoint, HttpMethod method)
    {
        // Rate limiting is especially important for these endpoints
        return endpoint.Contains("login", StringComparison.OrdinalIgnoreCase) ||
               endpoint.Contains("auth", StringComparison.OrdinalIgnoreCase) ||
               endpoint.Contains("password", StringComparison.OrdinalIgnoreCase) ||
               endpoint.Contains("reset", StringComparison.OrdinalIgnoreCase) ||
               endpoint.Contains("api", StringComparison.OrdinalIgnoreCase) ||
               endpoint.Contains("search", StringComparison.OrdinalIgnoreCase) ||
               endpoint.Contains("generate", StringComparison.OrdinalIgnoreCase) ||
               endpoint.Contains("send", StringComparison.OrdinalIgnoreCase) ||
               endpoint.Contains("email", StringComparison.OrdinalIgnoreCase) ||
               endpoint.Contains("sms", StringComparison.OrdinalIgnoreCase) ||
               true; // Test all endpoints
    }
    
    private async Task<RateLimitTest> TestBasicRateLimit(
        string endpoint,
        HttpMethod method,
        AuthenticationResult? authentication,
        CancellationToken cancellationToken)
    {
        const int requestCount = 100;
        const int timeWindowSeconds = 10;
        var successCount = 0;
        var rateLimitDetected = false;
        var stopwatch = Stopwatch.StartNew();
        
        for (int i = 0; i < requestCount; i++)
        {
            if (cancellationToken.IsCancellationRequested)
                break;
            
            var request = CreateRequest(endpoint, method, authentication);
            
            try
            {
                var response = await _httpClient.SendAsync(request, cancellationToken);
                
                if (IsRateLimited(response))
                {
                    rateLimitDetected = true;
                    break;
                }
                
                if (response.IsSuccessStatusCode)
                {
                    successCount++;
                }
            }
            catch (Exception)
            {
                // Ignore connection errors
            }
            
            // Stop if we've exceeded the time window
            if (stopwatch.Elapsed.TotalSeconds > timeWindowSeconds)
                break;
        }
        
        stopwatch.Stop();
        
        return new RateLimitTest
        {
            IsVulnerable = !rateLimitDetected && successCount > 50,
            Type = "No Rate Limiting",
            RequestCount = successCount,
            TimeWindow = stopwatch.Elapsed,
            Evidence = $"Sent {successCount} successful requests in {stopwatch.Elapsed.TotalSeconds:F1} seconds without rate limiting"
        };
    }
    
    private async Task<RateLimitTest> TestBurstRequests(
        string endpoint,
        HttpMethod method,
        AuthenticationResult? authentication,
        CancellationToken cancellationToken)
    {
        const int burstSize = 50;
        var tasks = new List<Task<HttpResponseMessage>>();
        var stopwatch = Stopwatch.StartNew();
        
        // Send burst of concurrent requests
        for (int i = 0; i < burstSize; i++)
        {
            var request = CreateRequest(endpoint, method, authentication);
            tasks.Add(_httpClient.SendAsync(request, cancellationToken));
        }
        
        var responses = await Task.WhenAll(tasks);
        stopwatch.Stop();
        
        var successCount = responses.Count(r => r.IsSuccessStatusCode);
        var rateLimitCount = responses.Count(r => IsRateLimited(r));
        
        return new RateLimitTest
        {
            IsVulnerable = rateLimitCount == 0 && successCount > burstSize * 0.8,
            Type = "No Burst Protection",
            RequestCount = successCount,
            TimeWindow = stopwatch.Elapsed,
            Evidence = $"Burst of {burstSize} concurrent requests resulted in {successCount} successes, {rateLimitCount} rate limited"
        };
    }
    
    private async Task<RateLimitTest> TestSlowRequests(
        string endpoint,
        HttpMethod method,
        AuthenticationResult? authentication,
        CancellationToken cancellationToken)
    {
        const int requestCount = 20;
        const int delayMs = 500;
        var successCount = 0;
        var rateLimitDetected = false;
        
        for (int i = 0; i < requestCount; i++)
        {
            if (cancellationToken.IsCancellationRequested)
                break;
            
            var request = CreateRequest(endpoint, method, authentication);
            
            try
            {
                var response = await _httpClient.SendAsync(request, cancellationToken);
                
                if (IsRateLimited(response))
                {
                    rateLimitDetected = true;
                    break;
                }
                
                if (response.IsSuccessStatusCode)
                {
                    successCount++;
                }
            }
            catch (Exception)
            {
                // Ignore connection errors
            }
            
            await Task.Delay(delayMs, cancellationToken);
        }
        
        return new RateLimitTest
        {
            IsVulnerable = false, // Slow requests typically shouldn't trigger rate limits
            Type = "Slow Request Pattern",
            RequestCount = successCount,
            Evidence = $"Slow requests ({delayMs}ms delay) completed {successCount}/{requestCount} successfully"
        };
    }
    
    private async Task<RateLimitTest> TestDifferentUserAgents(
        string endpoint,
        HttpMethod method,
        AuthenticationResult? authentication,
        CancellationToken cancellationToken)
    {
        var userAgents = new[]
        {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "curl/7.64.1",
            "PostmanRuntime/7.28.4",
            "python-requests/2.26.0"
        };
        
        var successCount = 0;
        const int requestsPerAgent = 20;
        
        foreach (var userAgent in userAgents)
        {
            for (int i = 0; i < requestsPerAgent; i++)
            {
                var request = CreateRequest(endpoint, method, authentication);
                request.Headers.TryAddWithoutValidation("User-Agent", userAgent);
                
                try
                {
                    var response = await _httpClient.SendAsync(request, cancellationToken);
                    
                    if (IsRateLimited(response))
                        break;
                    
                    if (response.IsSuccessStatusCode)
                        successCount++;
                }
                catch (Exception)
                {
                    // Ignore connection errors
                }
            }
        }
        
        var totalRequests = userAgents.Length * requestsPerAgent;
        var bypassSuccessful = successCount > totalRequests * 0.7;
        
        return new RateLimitTest
        {
            IsVulnerable = bypassSuccessful,
            Type = "User-Agent Bypass",
            RequestCount = successCount,
            Evidence = $"Changing User-Agent allowed {successCount}/{totalRequests} requests",
            Severity = bypassSuccessful ? VulnerabilitySeverity.Medium : VulnerabilitySeverity.Low
        };
    }
    
    private async Task<RateLimitTest> TestDifferentIPs(
        string endpoint,
        HttpMethod method,
        AuthenticationResult? authentication,
        CancellationToken cancellationToken)
    {
        var forwardedIPs = new[]
        {
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "8.8.8.8",
            "1.1.1.1",
            "::1",
            "2001:db8::1"
        };
        
        var successCount = 0;
        const int requestsPerIP = 20;
        
        foreach (var ip in forwardedIPs)
        {
            for (int i = 0; i < requestsPerIP; i++)
            {
                var request = CreateRequest(endpoint, method, authentication);
                request.Headers.TryAddWithoutValidation("X-Forwarded-For", ip);
                request.Headers.TryAddWithoutValidation("X-Real-IP", ip);
                request.Headers.TryAddWithoutValidation("X-Originating-IP", ip);
                
                try
                {
                    var response = await _httpClient.SendAsync(request, cancellationToken);
                    
                    if (IsRateLimited(response))
                        break;
                    
                    if (response.IsSuccessStatusCode)
                        successCount++;
                }
                catch (Exception)
                {
                    // Ignore connection errors
                }
            }
        }
        
        var totalRequests = forwardedIPs.Length * requestsPerIP;
        var bypassSuccessful = successCount > totalRequests * 0.7;
        
        return new RateLimitTest
        {
            IsVulnerable = bypassSuccessful,
            Type = "IP Spoofing Bypass",
            RequestCount = successCount,
            Evidence = $"Spoofing IP headers allowed {successCount}/{totalRequests} requests",
            Severity = bypassSuccessful ? VulnerabilitySeverity.High : VulnerabilitySeverity.Low
        };
    }
    
    private HttpRequestMessage CreateRequest(
        string endpoint,
        HttpMethod method,
        AuthenticationResult? authentication)
    {
        var request = new HttpRequestMessage(method, endpoint);
        
        if (authentication != null)
        {
            foreach (var header in authentication.Headers)
            {
                request.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }
        
        return request;
    }
    
    private bool IsRateLimited(HttpResponseMessage response)
    {
        // Check status code
        if ((int)response.StatusCode == 429) // Too Many Requests
            return true;
        
        // Check headers
        var rateLimitHeaders = new[]
        {
            "X-RateLimit-Remaining",
            "X-Rate-Limit-Remaining",
            "RateLimit-Remaining",
            "X-RateLimit-Limit",
            "Retry-After"
        };
        
        if (rateLimitHeaders.Any(header => response.Headers.Contains(header)))
        {
            // Check if remaining is 0
            if (response.Headers.TryGetValues("X-RateLimit-Remaining", out var values) ||
                response.Headers.TryGetValues("X-Rate-Limit-Remaining", out values))
            {
                if (int.TryParse(values.FirstOrDefault(), out var remaining) && remaining == 0)
                    return true;
            }
        }
        
        return false;
    }
    
    private Vulnerability CreateVulnerability(string endpoint, HttpMethod method, RateLimitTest test)
    {
        return new Vulnerability
        {
            Type = VulnerabilityTypes.RateLimiting,
            Severity = test.Severity,
            Title = $"Missing or Weak Rate Limiting - {test.Type}",
            Description = $"The endpoint lacks proper rate limiting. {test.Evidence}. " +
                         "This could allow attackers to perform brute force attacks, cause denial of service, or abuse API resources.",
            AffectedEndpoint = endpoint,
            HttpMethod = method.Method,
            PayloadUsed = $"{test.RequestCount} requests in {test.TimeWindow.TotalSeconds:F1} seconds",
            Evidence = test.Evidence,
            Remediation = "Implement proper rate limiting based on IP address, user account, or API key. " +
                         "Use exponential backoff for repeated failures. " +
                         "Consider implementing CAPTCHA for sensitive endpoints. " +
                         "Monitor and alert on unusual request patterns. " +
                         "Use a distributed rate limiting solution for scalability.",
            CweId = VulnerabilityTypes.CweIds[VulnerabilityTypes.RateLimiting],
            OwaspCategory = "A04:2021 - Insecure Design",
            ConfidenceScore = 0.85,
            Metadata = new Dictionary<string, object>
            {
                ["request_count"] = test.RequestCount,
                ["time_window_seconds"] = test.TimeWindow.TotalSeconds,
                ["bypass_method"] = test.Type
            }
        };
    }
    
    private class RateLimitTest
    {
        public bool IsVulnerable { get; set; }
        public string Type { get; set; } = string.Empty;
        public int RequestCount { get; set; }
        public TimeSpan TimeWindow { get; set; }
        public string Evidence { get; set; } = string.Empty;
        public VulnerabilitySeverity Severity { get; set; } = VulnerabilitySeverity.Medium;
    }
}