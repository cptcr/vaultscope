using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using VaultScope.Core.Constants;
using VaultScope.Core.Interfaces;
using VaultScope.Core.Models;
using VaultScope.Security.Payloads;

namespace VaultScope.Security.Detectors;

public class XssDetector : IVulnerabilityDetector
{
    private readonly HttpClient _httpClient;
    private readonly IUrlValidator _urlValidator;
    
    public VulnerabilityType Type => VulnerabilityType.CrossSiteScripting;
    public string Name => "Cross-Site Scripting (XSS) Detector";
    public string Description => "Detects XSS vulnerabilities in API responses";
    public int Priority => 95;
    
    public XssDetector(HttpClient httpClient, IUrlValidator urlValidator)
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
        
        var payloads = XssPayloads.GetPayloads();
        
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
                Console.WriteLine($"Error testing XSS: {ex.Message}");
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
        XssPayload payload,
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
            var response = await SendRequestAsync(testUrl, method, null, authentication, cancellationToken);
            
            if (await IsXssVulnerableAsync(response, payload))
            {
                return CreateVulnerability(endpoint, method, payload, $"query parameter '{key}'", response);
            }
            
            queryParams[key] = originalValue;
        }
        
        // Test request body
        if (method == HttpMethod.Post || method == HttpMethod.Put || method.Method == "PATCH")
        {
            var jsonBody = $"{{\"test\": \"{payload.Payload}\"}}";
            var response = await SendRequestAsync(endpoint, method, jsonBody, authentication, cancellationToken);
            
            if (await IsXssVulnerableAsync(response, payload))
            {
                return CreateVulnerability(endpoint, method, payload, "request body", response);
            }
        }
        
        // Test headers
        var headerResponse = await TestHeadersAsync(endpoint, method, payload, authentication, cancellationToken);
        if (headerResponse != null)
        {
            return CreateVulnerability(endpoint, method, payload, "HTTP headers", headerResponse);
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
    
    private async Task<HttpResponseMessage?> TestHeadersAsync(
        string url,
        HttpMethod method,
        XssPayload payload,
        AuthenticationResult? authentication,
        CancellationToken cancellationToken)
    {
        var headersToTest = new[] { "User-Agent", "Referer", "X-Forwarded-For", "X-Custom-Header" };
        
        foreach (var header in headersToTest)
        {
            var request = new HttpRequestMessage(method, url);
            
            if (authentication != null)
            {
                foreach (var authHeader in authentication.Headers)
                {
                    request.Headers.TryAddWithoutValidation(authHeader.Key, authHeader.Value);
                }
            }
            
            request.Headers.TryAddWithoutValidation(header, payload.Payload);
            
            var response = await _httpClient.SendAsync(request, cancellationToken);
            if (await IsXssVulnerableAsync(response, payload))
            {
                return response;
            }
        }
        
        return null;
    }
    
    private async Task<bool> IsXssVulnerableAsync(HttpResponseMessage response, XssPayload payload)
    {
        var content = await response.Content.ReadAsStringAsync();
        var contentType = response.Content.Headers.ContentType?.MediaType ?? "";
        
        // Check if payload is reflected without encoding
        if (content.Contains(payload.Payload, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        
        // Check for partial reflection that might still be exploitable
        if (payload.Indicators.Any(indicator => content.Contains(indicator, StringComparison.OrdinalIgnoreCase)))
        {
            // Additional checks for context-specific XSS
            if (IsHtmlContext(contentType) || IsJavaScriptContext(content))
            {
                return true;
            }
        }
        
        return false;
    }
    
    private bool IsHtmlContext(string contentType)
    {
        return contentType.Contains("html", StringComparison.OrdinalIgnoreCase);
    }
    
    private bool IsJavaScriptContext(string content)
    {
        var jsPatterns = new[] { "<script", "javascript:", "onerror=", "onload=", "onclick=" };
        return jsPatterns.Any(pattern => content.Contains(pattern, StringComparison.OrdinalIgnoreCase));
    }
    
    private Vulnerability CreateVulnerability(
        string endpoint,
        HttpMethod method,
        XssPayload payload,
        string location,
        HttpResponseMessage response)
    {
        return new Vulnerability
        {
            Type = VulnerabilityTypes.CrossSiteScripting,
            Severity = DetermineSeverity(payload),
            Title = $"{payload.Type} XSS Vulnerability Detected",
            Description = $"The {location} is vulnerable to {payload.Type} XSS attacks. " +
                         "User input is reflected in the response without proper encoding.",
            AffectedEndpoint = endpoint,
            HttpMethod = method.Method,
            PayloadUsed = payload.Payload,
            Evidence = $"Payload reflected in response: {payload.Payload}",
            Remediation = "Encode all user input before including it in HTML output. " +
                         "Use Content Security Policy (CSP) headers. " +
                         "Validate and sanitize all input on the server side.",
            CweId = VulnerabilityTypes.CweIds[VulnerabilityTypes.CrossSiteScripting],
            OwaspCategory = "A03:2021 - Injection",
            ConfidenceScore = 0.9
        };
    }
    
    private VulnerabilitySeverity DetermineSeverity(XssPayload payload)
    {
        return payload.Type switch
        {
            "Stored" => VulnerabilitySeverity.Critical,
            "Reflected" => VulnerabilitySeverity.High,
            "DOM-based" => VulnerabilitySeverity.High,
            _ => VulnerabilitySeverity.Medium
        };
    }
}