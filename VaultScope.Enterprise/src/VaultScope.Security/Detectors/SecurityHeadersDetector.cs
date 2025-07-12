using VaultScope.Core.Constants;
using VaultScope.Core.Interfaces;
using VaultScope.Core.Models;

namespace VaultScope.Security.Detectors;

public class SecurityHeadersDetector : IVulnerabilityDetector
{
    private readonly HttpClient _httpClient;
    private readonly IUrlValidator _urlValidator;
    
    public VulnerabilityType Type => VulnerabilityType.MissingSecurityHeaders;
    public string Name => "Security Headers Detector";
    public string Description => "Detects missing or misconfigured security headers";
    public int Priority => 60;
    
    public SecurityHeadersDetector(HttpClient httpClient, IUrlValidator urlValidator)
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
        
        var request = new HttpRequestMessage(method, endpoint);
        
        if (authentication != null)
        {
            foreach (var header in authentication.Headers)
            {
                request.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }
        
        try
        {
            var response = await _httpClient.SendAsync(request, cancellationToken);
            
            // Check for missing headers
            var missingHeaders = CheckMissingHeaders(response);
            if (missingHeaders.Any())
            {
                vulnerabilities.Add(CreateMissingHeadersVulnerability(endpoint, method, missingHeaders));
            }
            
            // Check for misconfigured headers
            var misconfiguredHeaders = CheckMisconfiguredHeaders(response);
            if (misconfiguredHeaders.Any())
            {
                vulnerabilities.Add(CreateMisconfiguredHeadersVulnerability(endpoint, method, misconfiguredHeaders));
            }
            
            // Check for deprecated headers
            var deprecatedHeaders = CheckDeprecatedHeaders(response);
            if (deprecatedHeaders.Any())
            {
                vulnerabilities.Add(CreateDeprecatedHeadersVulnerability(endpoint, method, deprecatedHeaders));
            }
            
            // Check for information disclosure headers
            var infoDisclosureHeaders = CheckInformationDisclosure(response);
            if (infoDisclosureHeaders.Any())
            {
                vulnerabilities.Add(CreateInfoDisclosureVulnerability(endpoint, method, infoDisclosureHeaders));
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error checking security headers: {ex.Message}");
        }
        
        return vulnerabilities;
    }
    
    public bool IsApplicable(string endpoint, HttpMethod method)
    {
        // Security headers should be checked on all endpoints
        return true;
    }
    
    private List<MissingHeader> CheckMissingHeaders(HttpResponseMessage response)
    {
        var missingHeaders = new List<MissingHeader>();
        
        foreach (var (header, recommendedValue) in SecurityHeaders.RequiredHeaders)
        {
            if (!response.Headers.Contains(header) && 
                !response.Content.Headers.Contains(header))
            {
                missingHeaders.Add(new MissingHeader
                {
                    Name = header,
                    RecommendedValue = recommendedValue,
                    Description = SecurityHeaders.HeaderDescriptions.GetValueOrDefault(header, "Security header")
                });
            }
        }
        
        return missingHeaders;
    }
    
    private List<MisconfiguredHeader> CheckMisconfiguredHeaders(HttpResponseMessage response)
    {
        var misconfigured = new List<MisconfiguredHeader>();
        
        // Check X-Frame-Options
        if (response.Headers.TryGetValues("X-Frame-Options", out var frameOptions))
        {
            var value = frameOptions.FirstOrDefault()?.ToUpperInvariant();
            if (value != "DENY" && value != "SAMEORIGIN")
            {
                misconfigured.Add(new MisconfiguredHeader
                {
                    Name = "X-Frame-Options",
                    CurrentValue = value ?? "",
                    RecommendedValue = "DENY or SAMEORIGIN",
                    Issue = "Weak clickjacking protection"
                });
            }
        }
        
        // Check Content-Security-Policy
        if (response.Headers.TryGetValues("Content-Security-Policy", out var csp))
        {
            var cspValue = csp.FirstOrDefault() ?? "";
            
            if (cspValue.Contains("unsafe-inline", StringComparison.OrdinalIgnoreCase))
            {
                misconfigured.Add(new MisconfiguredHeader
                {
                    Name = "Content-Security-Policy",
                    CurrentValue = cspValue,
                    Issue = "Allows unsafe inline scripts",
                    RecommendedValue = "Remove 'unsafe-inline' and use nonces or hashes"
                });
            }
            
            if (cspValue.Contains("unsafe-eval", StringComparison.OrdinalIgnoreCase))
            {
                misconfigured.Add(new MisconfiguredHeader
                {
                    Name = "Content-Security-Policy",
                    CurrentValue = cspValue,
                    Issue = "Allows unsafe eval()",
                    RecommendedValue = "Remove 'unsafe-eval'"
                });
            }
            
            if (cspValue.Contains("*", StringComparison.OrdinalIgnoreCase) && 
                !cspValue.Contains("*."))
            {
                misconfigured.Add(new MisconfiguredHeader
                {
                    Name = "Content-Security-Policy",
                    CurrentValue = cspValue,
                    Issue = "Uses wildcard source",
                    RecommendedValue = "Specify explicit sources instead of wildcards"
                });
            }
        }
        
        // Check Strict-Transport-Security
        if (response.Headers.TryGetValues("Strict-Transport-Security", out var hsts))
        {
            var hstsValue = hsts.FirstOrDefault() ?? "";
            
            if (!hstsValue.Contains("max-age", StringComparison.OrdinalIgnoreCase))
            {
                misconfigured.Add(new MisconfiguredHeader
                {
                    Name = "Strict-Transport-Security",
                    CurrentValue = hstsValue,
                    Issue = "Missing max-age directive",
                    RecommendedValue = "max-age=31536000; includeSubDomains"
                });
            }
            else
            {
                var maxAgeMatch = System.Text.RegularExpressions.Regex.Match(hstsValue, @"max-age=(\d+)");
                if (maxAgeMatch.Success && int.TryParse(maxAgeMatch.Groups[1].Value, out var maxAge))
                {
                    if (maxAge < 31536000) // Less than 1 year
                    {
                        misconfigured.Add(new MisconfiguredHeader
                        {
                            Name = "Strict-Transport-Security",
                            CurrentValue = hstsValue,
                            Issue = "max-age is too short",
                            RecommendedValue = "max-age=31536000 (1 year minimum)"
                        });
                    }
                }
            }
        }
        
        // Check Referrer-Policy
        if (response.Headers.TryGetValues("Referrer-Policy", out var referrerPolicy))
        {
            var policy = referrerPolicy.FirstOrDefault()?.ToLowerInvariant();
            var weakPolicies = new[] { "unsafe-url", "no-referrer-when-downgrade" };
            
            if (weakPolicies.Contains(policy))
            {
                misconfigured.Add(new MisconfiguredHeader
                {
                    Name = "Referrer-Policy",
                    CurrentValue = policy ?? "",
                    Issue = "Weak referrer policy",
                    RecommendedValue = "strict-origin-when-cross-origin or stricter"
                });
            }
        }
        
        return misconfigured;
    }
    
    private List<string> CheckDeprecatedHeaders(HttpResponseMessage response)
    {
        var deprecated = new List<string>();
        
        foreach (var header in SecurityHeaders.DeprecatedHeaders)
        {
            if (response.Headers.Contains(header))
            {
                deprecated.Add(header);
            }
        }
        
        return deprecated;
    }
    
    private List<InfoDisclosureHeader> CheckInformationDisclosure(HttpResponseMessage response)
    {
        var infoHeaders = new List<InfoDisclosureHeader>();
        
        // Server header
        if (response.Headers.TryGetValues("Server", out var server))
        {
            var serverValue = server.FirstOrDefault() ?? "";
            if (System.Text.RegularExpressions.Regex.IsMatch(serverValue, @"\d+\.\d+"))
            {
                infoHeaders.Add(new InfoDisclosureHeader
                {
                    Name = "Server",
                    Value = serverValue,
                    Risk = "Reveals server software and version"
                });
            }
        }
        
        // X-Powered-By
        if (response.Headers.Contains("X-Powered-By"))
        {
            infoHeaders.Add(new InfoDisclosureHeader
            {
                Name = "X-Powered-By",
                Value = response.Headers.GetValues("X-Powered-By").FirstOrDefault() ?? "",
                Risk = "Reveals technology stack"
            });
        }
        
        // X-AspNet-Version
        if (response.Headers.Contains("X-AspNet-Version"))
        {
            infoHeaders.Add(new InfoDisclosureHeader
            {
                Name = "X-AspNet-Version",
                Value = response.Headers.GetValues("X-AspNet-Version").FirstOrDefault() ?? "",
                Risk = "Reveals ASP.NET version"
            });
        }
        
        // X-AspNetMvc-Version
        if (response.Headers.Contains("X-AspNetMvc-Version"))
        {
            infoHeaders.Add(new InfoDisclosureHeader
            {
                Name = "X-AspNetMvc-Version",
                Value = response.Headers.GetValues("X-AspNetMvc-Version").FirstOrDefault() ?? "",
                Risk = "Reveals ASP.NET MVC version"
            });
        }
        
        return infoHeaders;
    }
    
    private Vulnerability CreateMissingHeadersVulnerability(
        string endpoint,
        HttpMethod method,
        List<MissingHeader> missingHeaders)
    {
        var headerList = string.Join(", ", missingHeaders.Select(h => h.Name));
        var details = string.Join("\n", missingHeaders.Select(h => 
            $"- {h.Name}: {h.Description}"));
        
        return new Vulnerability
        {
            Type = VulnerabilityTypes.MissingSecurityHeaders,
            Severity = VulnerabilitySeverity.Medium,
            Title = "Missing Security Headers",
            Description = $"The following security headers are missing: {headerList}. " +
                         "These headers provide defense-in-depth against various attacks.",
            AffectedEndpoint = endpoint,
            HttpMethod = method.Method,
            Evidence = $"Missing headers:\n{details}",
            Remediation = "Add the following security headers:\n" +
                         string.Join("\n", missingHeaders.Select(h => 
                             $"- {h.Name}: {h.RecommendedValue}")),
            CweId = VulnerabilityTypes.CweIds[VulnerabilityTypes.MissingSecurityHeaders],
            OwaspCategory = "A05:2021 - Security Misconfiguration",
            ConfidenceScore = 1.0,
            Metadata = new Dictionary<string, object>
            {
                ["missing_headers"] = missingHeaders.Select(h => h.Name).ToList()
            }
        };
    }
    
    private Vulnerability CreateMisconfiguredHeadersVulnerability(
        string endpoint,
        HttpMethod method,
        List<MisconfiguredHeader> misconfiguredHeaders)
    {
        var details = string.Join("\n", misconfiguredHeaders.Select(h => 
            $"- {h.Name}: {h.Issue} (Current: {h.CurrentValue})"));
        
        return new Vulnerability
        {
            Type = VulnerabilityTypes.SecurityMisconfiguration,
            Severity = VulnerabilitySeverity.Medium,
            Title = "Misconfigured Security Headers",
            Description = "Security headers are present but misconfigured, reducing their effectiveness.",
            AffectedEndpoint = endpoint,
            HttpMethod = method.Method,
            Evidence = $"Misconfigured headers:\n{details}",
            Remediation = "Fix the following security headers:\n" +
                         string.Join("\n", misconfiguredHeaders.Select(h => 
                             $"- {h.Name}: {h.RecommendedValue}")),
            CweId = VulnerabilityTypes.CweIds[VulnerabilityTypes.SecurityMisconfiguration],
            OwaspCategory = "A05:2021 - Security Misconfiguration",
            ConfidenceScore = 1.0,
            Metadata = new Dictionary<string, object>
            {
                ["misconfigured_headers"] = misconfiguredHeaders.Select(h => new
                {
                    header = h.Name,
                    issue = h.Issue,
                    current = h.CurrentValue
                }).ToList()
            }
        };
    }
    
    private Vulnerability CreateDeprecatedHeadersVulnerability(
        string endpoint,
        HttpMethod method,
        List<string> deprecatedHeaders)
    {
        return new Vulnerability
        {
            Type = VulnerabilityTypes.SecurityMisconfiguration,
            Severity = VulnerabilitySeverity.Low,
            Title = "Deprecated Security Headers",
            Description = $"Using deprecated security headers: {string.Join(", ", deprecatedHeaders)}. " +
                         "These headers may not be supported by modern browsers.",
            AffectedEndpoint = endpoint,
            HttpMethod = method.Method,
            Evidence = $"Deprecated headers found: {string.Join(", ", deprecatedHeaders)}",
            Remediation = "Remove deprecated headers and use modern alternatives:\n" +
                         "- X-XSS-Protection: Use Content-Security-Policy instead\n" +
                         "- Public-Key-Pins: Use Certificate Transparency instead\n" +
                         "- Expect-CT: No longer needed with Certificate Transparency",
            CweId = VulnerabilityTypes.CweIds[VulnerabilityTypes.SecurityMisconfiguration],
            OwaspCategory = "A05:2021 - Security Misconfiguration",
            ConfidenceScore = 1.0
        };
    }
    
    private Vulnerability CreateInfoDisclosureVulnerability(
        string endpoint,
        HttpMethod method,
        List<InfoDisclosureHeader> infoHeaders)
    {
        var details = string.Join("\n", infoHeaders.Select(h => 
            $"- {h.Name}: {h.Value} ({h.Risk})"));
        
        return new Vulnerability
        {
            Type = VulnerabilityTypes.SensitiveDataExposure,
            Severity = VulnerabilitySeverity.Low,
            Title = "Information Disclosure via Headers",
            Description = "Response headers reveal sensitive information about the server and technology stack.",
            AffectedEndpoint = endpoint,
            HttpMethod = method.Method,
            Evidence = $"Information disclosure headers:\n{details}",
            Remediation = "Remove or sanitize the following headers:\n" +
                         string.Join("\n", infoHeaders.Select(h => $"- {h.Name}")),
            CweId = VulnerabilityTypes.CweIds[VulnerabilityTypes.SensitiveDataExposure],
            OwaspCategory = "A01:2021 - Broken Access Control",
            ConfidenceScore = 1.0,
            Metadata = new Dictionary<string, object>
            {
                ["disclosed_headers"] = infoHeaders.Select(h => new
                {
                    header = h.Name,
                    value = h.Value,
                    risk = h.Risk
                }).ToList()
            }
        };
    }
    
    private class MissingHeader
    {
        public string Name { get; set; } = string.Empty;
        public string RecommendedValue { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
    }
    
    private class MisconfiguredHeader
    {
        public string Name { get; set; } = string.Empty;
        public string CurrentValue { get; set; } = string.Empty;
        public string RecommendedValue { get; set; } = string.Empty;
        public string Issue { get; set; } = string.Empty;
    }
    
    private class InfoDisclosureHeader
    {
        public string Name { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string Risk { get; set; } = string.Empty;
    }
}