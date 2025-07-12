using System.Text;
using VaultScope.Core.Constants;
using VaultScope.Core.Interfaces;
using VaultScope.Core.Models;

namespace VaultScope.Security.Detectors;

public class CommandInjectionDetector : IVulnerabilityDetector
{
    private readonly HttpClient _httpClient;
    private readonly IUrlValidator _urlValidator;
    
    public VulnerabilityType Type => VulnerabilityType.CommandInjection;
    public string Name => "Command Injection Detector";
    public string Description => "Detects OS command injection vulnerabilities";
    public int Priority => 85;
    
    public CommandInjectionDetector(HttpClient httpClient, IUrlValidator urlValidator)
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
        
        var payloads = GetCommandInjectionPayloads();
        
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
                Console.WriteLine($"Error testing command injection: {ex.Message}");
            }
        }
        
        return vulnerabilities;
    }
    
    public bool IsApplicable(string endpoint, HttpMethod method)
    {
        return true;
    }
    
    private async Task<Vulnerability?> TestPayloadAsync(
        string endpoint,
        HttpMethod method,
        CommandPayload payload,
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
            queryParams[key] = payload.Payload;
            
            var testUrl = $"{uri.GetLeftPart(UriPartial.Path)}?{queryParams}";
            
            var (isVulnerable, evidence) = await TestCommandInjectionAsync(testUrl, method, null, payload, authentication, cancellationToken);
            
            if (isVulnerable)
            {
                return CreateVulnerability(endpoint, method, payload, $"query parameter '{key}'", evidence);
            }
            
            queryParams[key] = originalValue;
        }
        
        // Test request body
        if (method == HttpMethod.Post || method == HttpMethod.Put || method.Method == "PATCH")
        {
            var jsonPayload = $"{{\"command\": \"{payload.Payload}\"}}";
            var (isVulnerable, evidence) = await TestCommandInjectionAsync(endpoint, method, jsonPayload, payload, authentication, cancellationToken);
            
            if (isVulnerable)
            {
                return CreateVulnerability(endpoint, method, payload, "request body", evidence);
            }
        }
        
        return null;
    }
    
    private async Task<(bool isVulnerable, string evidence)> TestCommandInjectionAsync(
        string url,
        HttpMethod method,
        string? body,
        CommandPayload payload,
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
        
        var startTime = DateTime.UtcNow;
        var response = await _httpClient.SendAsync(request, cancellationToken);
        var responseTime = (DateTime.UtcNow - startTime).TotalSeconds;
        var content = await response.Content.ReadAsStringAsync();
        
        // Check for command execution indicators
        if (payload.Type == "Time-based")
        {
            // For time-based payloads, check if response was delayed
            if (responseTime >= payload.ExpectedDelay)
            {
                return (true, $"Response delayed by {responseTime:F1} seconds");
            }
        }
        else
        {
            // Check for command output in response
            foreach (var indicator in payload.Indicators)
            {
                if (content.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                {
                    return (true, $"Command output detected: {indicator}");
                }
            }
            
            // Check for error messages indicating command execution
            var commandErrors = new[]
            {
                "sh: command not found",
                "bash: command not found",
                "cmd.exe",
                "/bin/sh",
                "permission denied",
                "cannot execute",
                "command failed",
                "system()",
                "exec()",
                "shell_exec()",
                "passthru()",
                "popen()"
            };
            
            foreach (var error in commandErrors)
            {
                if (content.Contains(error, StringComparison.OrdinalIgnoreCase))
                {
                    return (true, $"Command execution error detected: {error}");
                }
            }
        }
        
        return (false, string.Empty);
    }
    
    private Vulnerability CreateVulnerability(
        string endpoint,
        HttpMethod method,
        CommandPayload payload,
        string location,
        string evidence)
    {
        return new Vulnerability
        {
            Type = VulnerabilityTypes.CommandInjection,
            Severity = VulnerabilitySeverity.Critical,
            Title = "OS Command Injection Vulnerability Detected",
            Description = $"The {location} is vulnerable to OS command injection. " +
                         "An attacker can execute arbitrary system commands on the server.",
            AffectedEndpoint = endpoint,
            HttpMethod = method.Method,
            PayloadUsed = payload.Payload,
            Evidence = evidence,
            Remediation = "Never pass user input directly to system commands. " +
                         "Use parameterized commands or APIs instead of shell execution. " +
                         "Implement strict input validation with an allowlist approach. " +
                         "Run applications with minimal privileges. " +
                         "Use language-specific functions instead of OS commands where possible.",
            CweId = VulnerabilityTypes.CweIds[VulnerabilityTypes.CommandInjection],
            OwaspCategory = "A03:2021 - Injection",
            ConfidenceScore = 0.95,
            Metadata = new Dictionary<string, object>
            {
                ["injection_type"] = payload.Type,
                ["os_type"] = payload.OS
            }
        };
    }
    
    private List<CommandPayload> GetCommandInjectionPayloads()
    {
        return new List<CommandPayload>
        {
            // Basic command injection
            new CommandPayload
            {
                OS = "Unix",
                Type = "Basic",
                Payload = "; whoami",
                Indicators = new[] { "root", "www-data", "apache", "nginx" }
            },
            new CommandPayload
            {
                OS = "Unix",
                Type = "Basic",
                Payload = "| id",
                Indicators = new[] { "uid=", "gid=", "groups=" }
            },
            new CommandPayload
            {
                OS = "Windows",
                Type = "Basic",
                Payload = "& whoami",
                Indicators = new[] { "nt authority", "administrator", "user" }
            },
            
            // Command substitution
            new CommandPayload
            {
                OS = "Unix",
                Type = "Substitution",
                Payload = "$(whoami)",
                Indicators = new[] { "root", "www-data", "apache" }
            },
            new CommandPayload
            {
                OS = "Unix",
                Type = "Substitution",
                Payload = "`id`",
                Indicators = new[] { "uid=", "gid=" }
            },
            
            // Time-based blind injection
            new CommandPayload
            {
                OS = "Unix",
                Type = "Time-based",
                Payload = "; sleep 5",
                ExpectedDelay = 5,
                Indicators = Array.Empty<string>()
            },
            new CommandPayload
            {
                OS = "Windows",
                Type = "Time-based",
                Payload = "& ping -n 6 127.0.0.1",
                ExpectedDelay = 5,
                Indicators = Array.Empty<string>()
            },
            
            // Chained commands
            new CommandPayload
            {
                OS = "Unix",
                Type = "Chained",
                Payload = "; echo 'VaultScope-Test-5f4dcc3b5aa765d61d8327deb882cf99' > /tmp/test.txt; cat /tmp/test.txt",
                Indicators = new[] { "VaultScope-Test-5f4dcc3b5aa765d61d8327deb882cf99" }
            },
            new CommandPayload
            {
                OS = "Unix",
                Type = "Chained",
                Payload = "|| echo vulnerable",
                Indicators = new[] { "vulnerable" }
            },
            
            // Special characters bypass
            new CommandPayload
            {
                OS = "Unix",
                Type = "Bypass",
                Payload = ";wh$@oami",
                Indicators = new[] { "root", "www-data" }
            },
            new CommandPayload
            {
                OS = "Unix",
                Type = "Bypass",
                Payload = ";w\"h\"o\"a\"m\"i",
                Indicators = new[] { "root", "www-data" }
            },
            
            // Newline injection
            new CommandPayload
            {
                OS = "Unix",
                Type = "Newline",
                Payload = "\nwhoami",
                Indicators = new[] { "root", "www-data" }
            },
            new CommandPayload
            {
                OS = "Unix",
                Type = "Newline",
                Payload = "%0Awhoami",
                Indicators = new[] { "root", "www-data" }
            }
        };
    }
    
    private class CommandPayload
    {
        public string OS { get; set; } = "Unix";
        public string Type { get; set; } = "Basic";
        public string Payload { get; set; } = string.Empty;
        public string[] Indicators { get; set; } = Array.Empty<string>();
        public double ExpectedDelay { get; set; } = 0;
    }
}