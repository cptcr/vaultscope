using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using VaultScope.Core.Constants;
using VaultScope.Core.Interfaces;
using VaultScope.Core.Models;
using VaultScope.Security.Payloads;

namespace VaultScope.Security.Detectors;

public class SqlInjectionDetector : IVulnerabilityDetector
{
    private readonly HttpClient _httpClient;
    private readonly IUrlValidator _urlValidator;
    
    public VulnerabilityType Type => VulnerabilityType.SqlInjection;
    public string Name => "SQL Injection Detector";
    public string Description => "Detects SQL injection vulnerabilities in API endpoints";
    public int Priority => 100;
    
    public SqlInjectionDetector(HttpClient httpClient, IUrlValidator urlValidator)
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
        
        var payloads = SqlInjectionPayloads.GetPayloads();
        
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
                // Log exception but continue testing
                Console.WriteLine($"Error testing SQL injection: {ex.Message}");
            }
        }
        
        return vulnerabilities;
    }
    
    public bool IsApplicable(string endpoint, HttpMethod method)
    {
        // SQL injection testing is applicable to most endpoints
        return true;
    }
    
    private async Task<Vulnerability?> TestPayloadAsync(
        string endpoint,
        HttpMethod method,
        string payload,
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
            queryParams[key] = payload;
            
            var testUrl = $"{uri.GetLeftPart(UriPartial.Path)}?{queryParams}";
            var response = await SendRequestAsync(testUrl, method, null, authentication, cancellationToken);
            
            if (await IsSqlInjectionVulnerableAsync(response, payload))
            {
                return CreateVulnerability(endpoint, method, payload, key, response);
            }
            
            queryParams[key] = originalValue;
        }
        
        // Test request body for POST/PUT/PATCH
        if (method == HttpMethod.Post || method == HttpMethod.Put || method.Method == "PATCH")
        {
            var response = await SendRequestAsync(endpoint, method, payload, authentication, cancellationToken);
            
            if (await IsSqlInjectionVulnerableAsync(response, payload))
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
    
    private async Task<bool> IsSqlInjectionVulnerableAsync(HttpResponseMessage response, string payload)
    {
        var content = await response.Content.ReadAsStringAsync();
        
        // Check for SQL error messages
        var sqlErrors = new[]
        {
            "sql syntax",
            "mysql_fetch",
            "ORA-01756",
            "PostgreSQL",
            "SQLServer",
            "sqlite_",
            "SQL error",
            "mysql_",
            "mysqli_",
            "pg_query",
            "mssql_",
            "odbc_",
            "jdbc",
            "syntax error",
            "unclosed quotation mark",
            "unterminated string",
            "incorrect syntax near"
        };
        
        foreach (var error in sqlErrors)
        {
            if (content.Contains(error, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        
        // Check for timing-based detection
        if (payload.Contains("SLEEP") || payload.Contains("WAITFOR") || payload.Contains("pg_sleep"))
        {
            // For time-based payloads, we'd need to measure response time
            // This is a simplified check
            return response.Headers.Date.HasValue && 
                   (DateTime.UtcNow - response.Headers.Date.Value.UtcDateTime).TotalSeconds > 5;
        }
        
        return false;
    }
    
    private Vulnerability CreateVulnerability(
        string endpoint,
        HttpMethod method,
        string payload,
        string parameter,
        HttpResponseMessage response)
    {
        return new Vulnerability
        {
            Type = VulnerabilityTypes.SqlInjection,
            Severity = VulnerabilitySeverity.Critical,
            Title = "SQL Injection Vulnerability Detected",
            Description = $"The {parameter} parameter is vulnerable to SQL injection attacks. " +
                         "This could allow an attacker to view, modify, or delete database contents.",
            AffectedEndpoint = endpoint,
            HttpMethod = method.Method,
            PayloadUsed = payload,
            Evidence = $"SQL error detected in response when using payload: {payload}",
            Remediation = "Use parameterized queries or prepared statements. " +
                         "Validate and sanitize all user input. " +
                         "Apply the principle of least privilege to database accounts.",
            CweId = VulnerabilityTypes.CweIds[VulnerabilityTypes.SqlInjection],
            OwaspCategory = "A03:2021 - Injection",
            ConfidenceScore = 0.95
        };
    }
}