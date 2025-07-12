using System.Text;
using VaultScope.Core.Constants;
using VaultScope.Core.Interfaces;
using VaultScope.Core.Models;

namespace VaultScope.Security.Detectors;

public class AuthenticationBypassDetector : IVulnerabilityDetector
{
    private readonly HttpClient _httpClient;
    private readonly IUrlValidator _urlValidator;
    
    public VulnerabilityType Type => VulnerabilityType.AuthenticationBypass;
    public string Name => "Authentication Bypass Detector";
    public string Description => "Detects authentication bypass vulnerabilities";
    public int Priority => 100;
    
    public AuthenticationBypassDetector(HttpClient httpClient, IUrlValidator urlValidator)
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
        
        // Test various authentication bypass techniques
        var bypassTests = new List<AuthBypassTest>
        {
            await TestNoAuthentication(endpoint, method, authentication, cancellationToken),
            await TestSqlInjectionAuth(endpoint, method, cancellationToken),
            await TestDefaultCredentials(endpoint, method, cancellationToken),
            await TestJwtBypass(endpoint, method, cancellationToken),
            await TestSessionFixation(endpoint, method, cancellationToken),
            await TestApiKeyBypass(endpoint, method, cancellationToken),
            await TestHttpMethodOverride(endpoint, method, authentication, cancellationToken),
            await TestAuthHeaderManipulation(endpoint, method, cancellationToken)
        };
        
        foreach (var test in bypassTests)
        {
            if (test.IsVulnerable)
            {
                vulnerabilities.Add(CreateVulnerability(endpoint, method, test));
            }
        }
        
        return vulnerabilities;
    }
    
    public bool IsApplicable(string endpoint, HttpMethod method)
    {
        // Authentication testing is especially relevant for these endpoints
        return endpoint.Contains("admin", StringComparison.OrdinalIgnoreCase) ||
               endpoint.Contains("user", StringComparison.OrdinalIgnoreCase) ||
               endpoint.Contains("account", StringComparison.OrdinalIgnoreCase) ||
               endpoint.Contains("profile", StringComparison.OrdinalIgnoreCase) ||
               endpoint.Contains("dashboard", StringComparison.OrdinalIgnoreCase) ||
               endpoint.Contains("api", StringComparison.OrdinalIgnoreCase) ||
               endpoint.Contains("private", StringComparison.OrdinalIgnoreCase) ||
               endpoint.Contains("secure", StringComparison.OrdinalIgnoreCase) ||
               true; // Test all endpoints
    }
    
    private async Task<AuthBypassTest> TestNoAuthentication(
        string endpoint,
        HttpMethod method,
        AuthenticationResult? authentication,
        CancellationToken cancellationToken)
    {
        if (authentication == null)
        {
            return new AuthBypassTest { IsVulnerable = false };
        }
        
        // Try accessing with no authentication
        var request = new HttpRequestMessage(method, endpoint);
        var response = await _httpClient.SendAsync(request, cancellationToken);
        
        if (response.IsSuccessStatusCode)
        {
            // Compare with authenticated request
            var authRequest = new HttpRequestMessage(method, endpoint);
            foreach (var header in authentication.Headers)
            {
                authRequest.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
            var authResponse = await _httpClient.SendAsync(authRequest, cancellationToken);
            
            if (authResponse.IsSuccessStatusCode)
            {
                var noAuthContent = await response.Content.ReadAsStringAsync();
                var authContent = await authResponse.Content.ReadAsStringAsync();
                
                // If similar content is returned, authentication might be bypassed
                if (AreSimilarResponses(noAuthContent, authContent))
                {
                    return new AuthBypassTest
                    {
                        IsVulnerable = true,
                        Type = "No Authentication Required",
                        Payload = "No authentication headers sent",
                        Evidence = "Endpoint returns successful response without authentication"
                    };
                }
            }
        }
        
        return new AuthBypassTest { IsVulnerable = false };
    }
    
    private async Task<AuthBypassTest> TestSqlInjectionAuth(
        string endpoint,
        HttpMethod method,
        CancellationToken cancellationToken)
    {
        var authPayloads = new[]
        {
            "admin' OR '1'='1'--",
            "admin' OR '1'='1' #",
            "' OR '1'='1'--",
            "admin'--",
            "' OR 1=1--"
        };
        
        foreach (var payload in authPayloads)
        {
            var request = new HttpRequestMessage(method, endpoint);
            request.Headers.TryAddWithoutValidation("Authorization", $"Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes($"{payload}:password"))}");
            
            var response = await _httpClient.SendAsync(request, cancellationToken);
            
            if (response.IsSuccessStatusCode || await ContainsAuthSuccess(response))
            {
                return new AuthBypassTest
                {
                    IsVulnerable = true,
                    Type = "SQL Injection in Authentication",
                    Payload = payload,
                    Evidence = "Authentication bypassed using SQL injection"
                };
            }
        }
        
        return new AuthBypassTest { IsVulnerable = false };
    }
    
    private async Task<AuthBypassTest> TestDefaultCredentials(
        string endpoint,
        HttpMethod method,
        CancellationToken cancellationToken)
    {
        var defaultCreds = new[]
        {
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("root", "toor"),
            ("user", "user"),
            ("test", "test"),
            ("guest", "guest"),
            ("demo", "demo"),
            ("oracle", "oracle"),
            ("postgres", "postgres"),
            ("sa", "sa"),
            ("admin", ""),
            ("", "admin")
        };
        
        foreach (var (username, password) in defaultCreds)
        {
            var request = new HttpRequestMessage(method, endpoint);
            var authValue = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"));
            request.Headers.TryAddWithoutValidation("Authorization", $"Basic {authValue}");
            
            var response = await _httpClient.SendAsync(request, cancellationToken);
            
            if (response.IsSuccessStatusCode || await ContainsAuthSuccess(response))
            {
                return new AuthBypassTest
                {
                    IsVulnerable = true,
                    Type = "Default Credentials",
                    Payload = $"{username}:{password}",
                    Evidence = $"Default credentials accepted: {username}",
                    Severity = VulnerabilitySeverity.Critical
                };
            }
        }
        
        return new AuthBypassTest { IsVulnerable = false };
    }
    
    private async Task<AuthBypassTest> TestJwtBypass(
        string endpoint,
        HttpMethod method,
        CancellationToken cancellationToken)
    {
        var jwtBypassTokens = new[]
        {
            // None algorithm
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.",
            // Weak secret
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.ROy12msKSLGqCWVfqj0YDM-jbJJPXV8fK-pz3Y8e7Hs",
            // Empty signature
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.",
            // Algorithm confusion
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.rqtvW1gKzqpqj_QSjHNMdvHYJ2MBnc2MJgZhXH3AiGA"
        };
        
        foreach (var token in jwtBypassTokens)
        {
            var request = new HttpRequestMessage(method, endpoint);
            request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {token}");
            
            var response = await _httpClient.SendAsync(request, cancellationToken);
            
            if (response.IsSuccessStatusCode || await ContainsAuthSuccess(response))
            {
                return new AuthBypassTest
                {
                    IsVulnerable = true,
                    Type = "JWT Bypass",
                    Payload = token,
                    Evidence = "JWT validation bypassed",
                    Severity = VulnerabilitySeverity.Critical
                };
            }
        }
        
        return new AuthBypassTest { IsVulnerable = false };
    }
    
    private async Task<AuthBypassTest> TestSessionFixation(
        string endpoint,
        HttpMethod method,
        CancellationToken cancellationToken)
    {
        var fixedSessions = new[]
        {
            "PHPSESSID=admin",
            "JSESSIONID=admin",
            "ASP.NET_SessionId=admin",
            "session=admin",
            "sid=admin",
            "token=admin"
        };
        
        foreach (var session in fixedSessions)
        {
            var request = new HttpRequestMessage(method, endpoint);
            request.Headers.TryAddWithoutValidation("Cookie", session);
            
            var response = await _httpClient.SendAsync(request, cancellationToken);
            
            if (response.IsSuccessStatusCode || await ContainsAuthSuccess(response))
            {
                return new AuthBypassTest
                {
                    IsVulnerable = true,
                    Type = "Session Fixation",
                    Payload = session,
                    Evidence = "Fixed session ID accepted"
                };
            }
        }
        
        return new AuthBypassTest { IsVulnerable = false };
    }
    
    private async Task<AuthBypassTest> TestApiKeyBypass(
        string endpoint,
        HttpMethod method,
        CancellationToken cancellationToken)
    {
        var apiKeyTests = new Dictionary<string, string>
        {
            ["X-API-Key"] = "test",
            ["X-Api-Key"] = "' OR '1'='1",
            ["API-Key"] = "admin",
            ["apikey"] = "../../../",
            ["X-Auth-Token"] = "null",
            ["Authorization"] = "API-Key test"
        };
        
        foreach (var (header, value) in apiKeyTests)
        {
            var request = new HttpRequestMessage(method, endpoint);
            request.Headers.TryAddWithoutValidation(header, value);
            
            var response = await _httpClient.SendAsync(request, cancellationToken);
            
            if (response.IsSuccessStatusCode || await ContainsAuthSuccess(response))
            {
                return new AuthBypassTest
                {
                    IsVulnerable = true,
                    Type = "API Key Bypass",
                    Payload = $"{header}: {value}",
                    Evidence = "Weak API key validation"
                };
            }
        }
        
        return new AuthBypassTest { IsVulnerable = false };
    }
    
    private async Task<AuthBypassTest> TestHttpMethodOverride(
        string endpoint,
        HttpMethod method,
        AuthenticationResult? authentication,
        CancellationToken cancellationToken)
    {
        var overrideMethods = new[] { "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD" };
        
        foreach (var overrideMethod in overrideMethods)
        {
            if (overrideMethod == method.Method) continue;
            
            var request = new HttpRequestMessage(new HttpMethod(overrideMethod), endpoint);
            
            // Add method override headers
            request.Headers.TryAddWithoutValidation("X-HTTP-Method-Override", method.Method);
            request.Headers.TryAddWithoutValidation("X-HTTP-Method", method.Method);
            request.Headers.TryAddWithoutValidation("X-Method-Override", method.Method);
            
            var response = await _httpClient.SendAsync(request, cancellationToken);
            
            if (response.IsSuccessStatusCode)
            {
                // Test if it behaves like the original method
                var originalRequest = new HttpRequestMessage(method, endpoint);
                if (authentication != null)
                {
                    foreach (var header in authentication.Headers)
                    {
                        originalRequest.Headers.TryAddWithoutValidation(header.Key, header.Value);
                    }
                }
                var originalResponse = await _httpClient.SendAsync(originalRequest, cancellationToken);
                
                if (AreSimilarResponses(
                    await response.Content.ReadAsStringAsync(),
                    await originalResponse.Content.ReadAsStringAsync()))
                {
                    return new AuthBypassTest
                    {
                        IsVulnerable = true,
                        Type = "HTTP Method Override",
                        Payload = $"{overrideMethod} with X-HTTP-Method-Override: {method.Method}",
                        Evidence = "Authentication bypassed using method override"
                    };
                }
            }
        }
        
        return new AuthBypassTest { IsVulnerable = false };
    }
    
    private async Task<AuthBypassTest> TestAuthHeaderManipulation(
        string endpoint,
        HttpMethod method,
        CancellationToken cancellationToken)
    {
        var manipulations = new Dictionary<string, string>
        {
            ["Authorization"] = "Bearer undefined",
            ["Authorization"] = "Bearer null",
            ["Authorization"] = "Bearer [object Object]",
            ["Authorization"] = "Bearer ",
            ["Authorization"] = "Basic Og==", // Empty username and password
            ["X-Forwarded-User"] = "admin",
            ["X-Forwarded-For"] = "127.0.0.1",
            ["X-Real-IP"] = "127.0.0.1",
            ["X-Originating-IP"] = "127.0.0.1",
            ["X-Remote-User"] = "admin",
            ["X-User"] = "admin",
            ["X-Username"] = "admin"
        };
        
        foreach (var (header, value) in manipulations)
        {
            var request = new HttpRequestMessage(method, endpoint);
            request.Headers.TryAddWithoutValidation(header, value);
            
            var response = await _httpClient.SendAsync(request, cancellationToken);
            
            if (response.IsSuccessStatusCode || await ContainsAuthSuccess(response))
            {
                return new AuthBypassTest
                {
                    IsVulnerable = true,
                    Type = "Header Manipulation",
                    Payload = $"{header}: {value}",
                    Evidence = "Authentication bypassed through header manipulation"
                };
            }
        }
        
        return new AuthBypassTest { IsVulnerable = false };
    }
    
    private async Task<bool> ContainsAuthSuccess(HttpResponseMessage response)
    {
        var content = await response.Content.ReadAsStringAsync();
        var successIndicators = new[]
        {
            "welcome",
            "dashboard",
            "profile",
            "logout",
            "success",
            "authenticated",
            "token",
            "session",
            "\"role\":",
            "\"admin\":",
            "\"user\":"
        };
        
        return successIndicators.Any(indicator => 
            content.Contains(indicator, StringComparison.OrdinalIgnoreCase));
    }
    
    private bool AreSimilarResponses(string response1, string response2)
    {
        // Simple similarity check - can be enhanced
        if (response1.Length == 0 || response2.Length == 0)
            return false;
        
        // Check if responses are very similar in length
        var lengthRatio = (double)Math.Min(response1.Length, response2.Length) / 
                         Math.Max(response1.Length, response2.Length);
        
        return lengthRatio > 0.8;
    }
    
    private Vulnerability CreateVulnerability(string endpoint, HttpMethod method, AuthBypassTest test)
    {
        return new Vulnerability
        {
            Type = VulnerabilityTypes.AuthenticationBypass,
            Severity = test.Severity,
            Title = $"Authentication Bypass via {test.Type}",
            Description = $"The endpoint is vulnerable to authentication bypass using {test.Type}. " +
                         "An attacker can gain unauthorized access to protected resources.",
            AffectedEndpoint = endpoint,
            HttpMethod = method.Method,
            PayloadUsed = test.Payload,
            Evidence = test.Evidence,
            Remediation = GetRemediation(test.Type),
            CweId = VulnerabilityTypes.CweIds[VulnerabilityTypes.AuthenticationBypass],
            OwaspCategory = "A07:2021 - Identification and Authentication Failures",
            ConfidenceScore = 0.95
        };
    }
    
    private string GetRemediation(string bypassType)
    {
        return bypassType switch
        {
            "Default Credentials" => "Change all default credentials. Implement strong password policies. " +
                                   "Force password changes on first login.",
            "SQL Injection in Authentication" => "Use parameterized queries for authentication. " +
                                               "Never concatenate user input in SQL queries.",
            "JWT Bypass" => "Properly validate JWT signatures. Reject 'none' algorithm. " +
                           "Use strong secrets and validate all claims.",
            "No Authentication Required" => "Implement proper authentication for all sensitive endpoints. " +
                                          "Use a centralized authentication mechanism.",
            "Session Fixation" => "Regenerate session IDs after login. " +
                                 "Validate session tokens properly.",
            "API Key Bypass" => "Implement strong API key validation. " +
                               "Use cryptographically secure tokens.",
            "HTTP Method Override" => "Disable method override headers. " +
                                    "Apply authentication to all HTTP methods.",
            "Header Manipulation" => "Don't trust client-provided headers for authentication. " +
                                   "Validate all authentication tokens server-side.",
            _ => "Implement strong authentication mechanisms. " +
                 "Follow authentication best practices."
        };
    }
    
    private class AuthBypassTest
    {
        public bool IsVulnerable { get; set; }
        public string Type { get; set; } = string.Empty;
        public string Payload { get; set; } = string.Empty;
        public string Evidence { get; set; } = string.Empty;
        public VulnerabilitySeverity Severity { get; set; } = VulnerabilitySeverity.High;
    }
}