using System.Text;
using VaultScope.Core.Constants;
using VaultScope.Core.Interfaces;
using VaultScope.Core.Models;

namespace VaultScope.Security.Detectors;

public class PathTraversalDetector : IVulnerabilityDetector
{
    private readonly HttpClient _httpClient;
    private readonly IUrlValidator _urlValidator;
    
    public VulnerabilityType Type => VulnerabilityType.PathTraversal;
    public string Name => "Path Traversal Detector";
    public string Description => "Detects directory traversal and local file inclusion vulnerabilities";
    public int Priority => 80;
    
    public PathTraversalDetector(HttpClient httpClient, IUrlValidator urlValidator)
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
        
        var payloads = GetPathTraversalPayloads();
        
        foreach (var payload in payloads)
        {
            try
            {
                var vulnerability = await TestPayloadAsync(endpoint, method, payload, authentication, cancellationToken);
                if (vulnerability != null)
                {
                    vulnerabilities.Add(vulnerability);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error testing path traversal: {ex.Message}");
            }
        }
        
        return vulnerabilities;
    }
    
    public bool IsApplicable(string endpoint, HttpMethod method)
    {
        // Path traversal is more common in endpoints that handle files
        return endpoint.Contains("file", StringComparison.OrdinalIgnoreCase) ||
               endpoint.Contains("path", StringComparison.OrdinalIgnoreCase) ||
               endpoint.Contains("download", StringComparison.OrdinalIgnoreCase) ||
               endpoint.Contains("upload", StringComparison.OrdinalIgnoreCase) ||
               endpoint.Contains("image", StringComparison.OrdinalIgnoreCase) ||
               endpoint.Contains("document", StringComparison.OrdinalIgnoreCase) ||
               endpoint.Contains("template", StringComparison.OrdinalIgnoreCase) ||
               endpoint.Contains("include", StringComparison.OrdinalIgnoreCase) ||
               true; // Test all endpoints
    }
    
    private async Task<Vulnerability?> TestPayloadAsync(
        string endpoint,
        HttpMethod method,
        PathPayload payload,
        AuthenticationResult? authentication,
        CancellationToken cancellationToken)
    {
        var uri = new Uri(endpoint);
        var queryParams = System.Web.HttpUtility.ParseQueryString(uri.Query);
        
        // Test query parameters
        foreach (var key in queryParams.AllKeys)
        {
            if (key == null) continue;
            
            var originalValue = queryParams[key];
            queryParams[key] = payload.Path;
            
            var testUrl = $"{uri.GetLeftPart(UriPartial.Path)}?{queryParams}";
            var response = await SendRequestAsync(testUrl, method, null, authentication, cancellationToken);
            
            if (await IsPathTraversalVulnerableAsync(response, payload))
            {
                return CreateVulnerability(endpoint, method, payload, $"query parameter '{key}'", response);
            }
            
            queryParams[key] = originalValue;
        }
        
        // Test path segments
        if (uri.Segments.Length > 0)
        {
            for (int i = uri.Segments.Length - 1; i >= 0; i--)
            {
                var segments = uri.Segments.ToList();
                var originalSegment = segments[i];
                
                // Skip if it's just a slash
                if (originalSegment == "/") continue;
                
                segments[i] = payload.Path + "/";
                var testPath = string.Join("", segments);
                var testUrl = $"{uri.Scheme}://{uri.Authority}{testPath}";
                
                if (uri.Query.Length > 0)
                {
                    testUrl += uri.Query;
                }
                
                var response = await SendRequestAsync(testUrl, method, null, authentication, cancellationToken);
                
                if (await IsPathTraversalVulnerableAsync(response, payload))
                {
                    return CreateVulnerability(endpoint, method, payload, $"path segment {i}", response);
                }
            }
        }
        
        // Test request body
        if (method == HttpMethod.Post || method == HttpMethod.Put || method.Method == "PATCH")
        {
            var jsonPayload = $"{{\"file\": \"{payload.Path}\", \"path\": \"{payload.Path}\"}}";
            var response = await SendRequestAsync(endpoint, method, jsonPayload, authentication, cancellationToken);
            
            if (await IsPathTraversalVulnerableAsync(response, payload))
            {
                return CreateVulnerability(endpoint, method, payload, "request body", response);
            }
        }
        
        return null;
    }
    
    private async Task<HttpResponseMessage> SendRequestAsync(
        string url,
        HttpMethod method,
        string? body,
        AuthenticationResult? authentication,
        CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(method, url);
        
        if (authentication != null)
        {
            foreach (var header in authentication.Headers)
            {
                request.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }
        
        if (!string.IsNullOrEmpty(body))
        {
            request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        }
        
        return await _httpClient.SendAsync(request, cancellationToken);
    }
    
    private async Task<bool> IsPathTraversalVulnerableAsync(HttpResponseMessage response, PathPayload payload)
    {
        var content = await response.Content.ReadAsStringAsync();
        
        // Check for file content indicators
        foreach (var indicator in payload.Indicators)
        {
            if (content.Contains(indicator, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        
        // Check for error messages that might indicate path traversal
        var pathErrors = new[]
        {
            "no such file or directory",
            "file not found",
            "cannot open",
            "permission denied",
            "access denied",
            "invalid path",
            "directory traversal",
            "../",
            "..\\",
            payload.Path
        };
        
        // Sometimes the error message contains the attempted path
        if (pathErrors.Any(error => content.Contains(error, StringComparison.OrdinalIgnoreCase)))
        {
            // Double-check with indicators to reduce false positives
            if (payload.SecondaryIndicators.Any(ind => content.Contains(ind, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }
        
        return false;
    }
    
    private Vulnerability CreateVulnerability(
        string endpoint,
        HttpMethod method,
        PathPayload payload,
        string location,
        HttpResponseMessage response)
    {
        return new Vulnerability
        {
            Type = VulnerabilityTypes.PathTraversal,
            Severity = payload.Severity,
            Title = "Path Traversal Vulnerability Detected",
            Description = $"The {location} is vulnerable to path traversal attacks. " +
                         $"An attacker can access {payload.Description} outside the intended directory.",
            AffectedEndpoint = endpoint,
            HttpMethod = method.Method,
            PayloadUsed = payload.Path,
            Evidence = $"Successfully accessed {payload.TargetFile} using path traversal",
            Remediation = "Validate and sanitize all file paths. " +
                         "Use a whitelist of allowed files or directories. " +
                         "Resolve paths to their canonical form and ensure they're within allowed directories. " +
                         "Avoid passing user input directly to file system operations. " +
                         "Use platform-specific APIs that prevent path traversal.",
            CweId = VulnerabilityTypes.CweIds[VulnerabilityTypes.PathTraversal],
            OwaspCategory = "A01:2021 - Broken Access Control",
            ConfidenceScore = 0.9,
            Metadata = new Dictionary<string, object>
            {
                ["target_file"] = payload.TargetFile,
                ["traversal_depth"] = payload.Path.Count(c => c == '.')
            }
        };
    }
    
    private List<PathPayload> GetPathTraversalPayloads()
    {
        return new List<PathPayload>
        {
            // Unix/Linux payloads
            new PathPayload
            {
                Path = "../../../etc/passwd",
                TargetFile = "/etc/passwd",
                Description = "system password file",
                Indicators = new[] { "root:x:0:0", "nobody:x:", "/bin/bash", "/bin/sh" },
                SecondaryIndicators = new[] { "daemon:", "sys:", "www-data:" },
                Severity = VulnerabilitySeverity.High
            },
            new PathPayload
            {
                Path = "../../../../etc/passwd",
                TargetFile = "/etc/passwd",
                Description = "system password file",
                Indicators = new[] { "root:x:0:0", "nobody:x:", "/bin/bash" },
                SecondaryIndicators = new[] { "daemon:", "sys:" },
                Severity = VulnerabilitySeverity.High
            },
            new PathPayload
            {
                Path = "../../../../../etc/passwd",
                TargetFile = "/etc/passwd",
                Description = "system password file",
                Indicators = new[] { "root:x:0:0", "nobody:x:" },
                SecondaryIndicators = new[] { "daemon:" },
                Severity = VulnerabilitySeverity.High
            },
            
            // Windows payloads
            new PathPayload
            {
                Path = "..\\..\\..\\windows\\win.ini",
                TargetFile = "C:\\Windows\\win.ini",
                Description = "Windows configuration file",
                Indicators = new[] { "[fonts]", "[extensions]", "[mci extensions]", "[files]" },
                SecondaryIndicators = new[] { "MAPI=", "CMC=" },
                Severity = VulnerabilitySeverity.High
            },
            new PathPayload
            {
                Path = "..\\..\\..\\..\\windows\\win.ini",
                TargetFile = "C:\\Windows\\win.ini",
                Description = "Windows configuration file",
                Indicators = new[] { "[fonts]", "[extensions]" },
                SecondaryIndicators = new[] { "MAPI=" },
                Severity = VulnerabilitySeverity.High
            },
            
            // URL encoded payloads
            new PathPayload
            {
                Path = "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                TargetFile = "/etc/passwd",
                Description = "system password file (URL encoded)",
                Indicators = new[] { "root:x:0:0", "nobody:x:" },
                SecondaryIndicators = new[] { "daemon:" },
                Severity = VulnerabilitySeverity.High
            },
            new PathPayload
            {
                Path = "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
                TargetFile = "C:\\Windows\\win.ini",
                Description = "Windows configuration file (URL encoded)",
                Indicators = new[] { "[fonts]", "[extensions]" },
                SecondaryIndicators = new[] { "MAPI=" },
                Severity = VulnerabilitySeverity.High
            },
            
            // Double encoding
            new PathPayload
            {
                Path = "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
                TargetFile = "/etc/passwd",
                Description = "system password file (double encoded)",
                Indicators = new[] { "root:x:0:0" },
                SecondaryIndicators = new[] { "nobody:x:" },
                Severity = VulnerabilitySeverity.High
            },
            
            // Unicode encoding
            new PathPayload
            {
                Path = "..%c0%af..%c0%afetc%c0%afpasswd",
                TargetFile = "/etc/passwd",
                Description = "system password file (Unicode)",
                Indicators = new[] { "root:x:0:0" },
                SecondaryIndicators = new[] { "nobody:x:" },
                Severity = VulnerabilitySeverity.High
            },
            
            // Null byte injection
            new PathPayload
            {
                Path = "../../../etc/passwd%00.jpg",
                TargetFile = "/etc/passwd",
                Description = "system password file (null byte)",
                Indicators = new[] { "root:x:0:0" },
                SecondaryIndicators = new[] { "nobody:x:" },
                Severity = VulnerabilitySeverity.Critical
            },
            
            // Absolute path
            new PathPayload
            {
                Path = "/etc/passwd",
                TargetFile = "/etc/passwd",
                Description = "system password file (absolute path)",
                Indicators = new[] { "root:x:0:0" },
                SecondaryIndicators = new[] { "nobody:x:" },
                Severity = VulnerabilitySeverity.Medium
            },
            new PathPayload
            {
                Path = "C:\\Windows\\win.ini",
                TargetFile = "C:\\Windows\\win.ini",
                Description = "Windows configuration file (absolute path)",
                Indicators = new[] { "[fonts]" },
                SecondaryIndicators = new[] { "[extensions]" },
                Severity = VulnerabilitySeverity.Medium
            }
        };
    }
    
    private class PathPayload
    {
        public string Path { get; set; } = string.Empty;
        public string TargetFile { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string[] Indicators { get; set; } = Array.Empty<string>();
        public string[] SecondaryIndicators { get; set; } = Array.Empty<string>();
        public VulnerabilitySeverity Severity { get; set; } = VulnerabilitySeverity.High;
    }
}