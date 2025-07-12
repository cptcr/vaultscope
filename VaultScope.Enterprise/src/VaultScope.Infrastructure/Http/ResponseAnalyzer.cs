using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace VaultScope.Infrastructure.Http;

public class ResponseAnalyzer
{
    private readonly ILogger<ResponseAnalyzer> _logger;
    
    // Common error patterns
    private static readonly List<ErrorPattern> ErrorPatterns = new()
    {
        // SQL Errors
        new ErrorPattern("SQL Syntax Error", @"sql syntax|syntax error.*sql|you have an error in your sql", ErrorType.SqlError),
        new ErrorPattern("MySQL Error", @"mysql_fetch|mysqli_error|mysql_error|mysqli_fetch", ErrorType.SqlError),
        new ErrorPattern("PostgreSQL Error", @"pg_query|pg_exec|pg_execute|postgresql error", ErrorType.SqlError),
        new ErrorPattern("Oracle Error", @"ORA-\d{5}|oracle error|oci_error", ErrorType.SqlError),
        new ErrorPattern("MSSQL Error", @"microsoft sql server|mssql_query|sqlsrv_errors", ErrorType.SqlError),
        
        // Programming Language Errors
        new ErrorPattern("PHP Error", @"<b>Warning</b>:|<b>Fatal error</b>:|<b>Notice</b>:|php error|call to undefined", ErrorType.ApplicationError),
        new ErrorPattern("ASP.NET Error", @"asp\.net|\.net framework|system\.web\.|microsoft\.aspnet", ErrorType.ApplicationError),
        new ErrorPattern("Java Error", @"java\.lang\.|javax\.|org\.springframework|stacktrace.*java", ErrorType.ApplicationError),
        new ErrorPattern("Python Error", @"traceback \(most recent call last\)|python error|django\..*error", ErrorType.ApplicationError),
        new ErrorPattern("Ruby Error", @"ruby on rails|sinatra|activerecord::|nomethoderror", ErrorType.ApplicationError),
        
        // Server Errors
        new ErrorPattern("Apache Error", @"apache/[\d\.]+|mod_.*\.c|apache error", ErrorType.ServerError),
        new ErrorPattern("Nginx Error", @"nginx/[\d\.]+|nginx error", ErrorType.ServerError),
        new ErrorPattern("IIS Error", @"iis/[\d\.]+|microsoft-iis", ErrorType.ServerError),
        
        // Path Disclosure
        new ErrorPattern("Unix Path", @"/etc/passwd|/var/www|/home/\w+|/usr/local", ErrorType.PathDisclosure),
        new ErrorPattern("Windows Path", @"[A-Z]:\\.*\\|C:\\Windows|C:\\inetpub", ErrorType.PathDisclosure),
        
        // Configuration Errors
        new ErrorPattern("Debug Mode", @"debug.*true|development mode|stacktrace|call stack", ErrorType.ConfigurationError),
        new ErrorPattern("Config File", @"config\.php|web\.config|settings\.py|database\.yml", ErrorType.ConfigurationError)
    };
    
    public ResponseAnalyzer(ILogger<ResponseAnalyzer> logger)
    {
        _logger = logger;
    }
    
    public async Task<ResponseAnalysis> AnalyzeAsync(HttpResponseMessage response)
    {
        var analysis = new ResponseAnalysis
        {
            StatusCode = response.StatusCode,
            Headers = ExtractHeaders(response),
            ResponseTime = DateTime.UtcNow // This would ideally be calculated from request start time
        };
        
        try
        {
            var content = await response.Content.ReadAsStringAsync();
            analysis.ContentLength = content.Length;
            analysis.ContentType = response.Content.Headers.ContentType?.MediaType ?? "unknown";
            
            // Analyze content
            analysis.DetectedErrors = DetectErrors(content);
            analysis.SensitiveData = DetectSensitiveData(content);
            analysis.TechnologyStack = DetectTechnologyStack(response, content);
            analysis.SecurityIndicators = DetectSecurityIndicators(response, content);
            
            // Try to parse as JSON
            if (IsJsonContent(analysis.ContentType))
            {
                try
                {
                    analysis.JsonStructure = JsonSerializer.Deserialize<JsonElement>(content);
                    analysis.IsValidJson = true;
                }
                catch
                {
                    analysis.IsValidJson = false;
                }
            }
            
            // Extract forms and links
            if (IsHtmlContent(analysis.ContentType))
            {
                analysis.Forms = ExtractForms(content);
                analysis.Links = ExtractLinks(content);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error analyzing response");
        }
        
        return analysis;
    }
    
    private Dictionary<string, List<string>> ExtractHeaders(HttpResponseMessage response)
    {
        var headers = new Dictionary<string, List<string>>();
        
        foreach (var header in response.Headers)
        {
            headers[header.Key] = header.Value.ToList();
        }
        
        foreach (var header in response.Content.Headers)
        {
            headers[header.Key] = header.Value.ToList();
        }
        
        return headers;
    }
    
    private List<DetectedError> DetectErrors(string content)
    {
        var errors = new List<DetectedError>();
        
        foreach (var pattern in ErrorPatterns)
        {
            var matches = Regex.Matches(content, pattern.Pattern, RegexOptions.IgnoreCase | RegexOptions.Multiline);
            
            foreach (Match match in matches)
            {
                errors.Add(new DetectedError
                {
                    Type = pattern.Type,
                    Description = pattern.Description,
                    Evidence = match.Value,
                    Position = match.Index
                });
            }
        }
        
        return errors;
    }
    
    private List<SensitiveDataLeak> DetectSensitiveData(string content)
    {
        var leaks = new List<SensitiveDataLeak>();
        
        // API Keys
        var apiKeyPatterns = new[]
        {
            @"api[_-]?key[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9_\-]{20,})",
            @"apikey[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9_\-]{20,})",
            @"[\"']api_key[\"']\s*:\s*[\"']([^\"']+)[\"']"
        };
        
        foreach (var pattern in apiKeyPatterns)
        {
            var matches = Regex.Matches(content, pattern, RegexOptions.IgnoreCase);
            foreach (Match match in matches)
            {
                leaks.Add(new SensitiveDataLeak
                {
                    Type = "API Key",
                    Evidence = match.Value,
                    Severity = "High"
                });
            }
        }
        
        // Passwords
        var passwordPatterns = new[]
        {
            @"password[\"']?\s*[:=]\s*[\"']?([^\"'\s]{4,})",
            @"pwd[\"']?\s*[:=]\s*[\"']?([^\"'\s]{4,})",
            @"[\"']password[\"']\s*:\s*[\"']([^\"']+)[\"']"
        };
        
        foreach (var pattern in passwordPatterns)
        {
            var matches = Regex.Matches(content, pattern, RegexOptions.IgnoreCase);
            foreach (Match match in matches)
            {
                if (!match.Value.Contains("****") && !match.Value.Contains("hidden"))
                {
                    leaks.Add(new SensitiveDataLeak
                    {
                        Type = "Password",
                        Evidence = match.Value,
                        Severity = "Critical"
                    });
                }
            }
        }
        
        // Email addresses
        var emailPattern = @"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b";
        var emailMatches = Regex.Matches(content, emailPattern);
        
        if (emailMatches.Count > 5) // Only flag if many emails are exposed
        {
            leaks.Add(new SensitiveDataLeak
            {
                Type = "Email Addresses",
                Evidence = $"Found {emailMatches.Count} email addresses",
                Severity = "Medium"
            });
        }
        
        // Credit card patterns (simplified)
        var ccPattern = @"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b";
        if (Regex.IsMatch(content, ccPattern))
        {
            leaks.Add(new SensitiveDataLeak
            {
                Type = "Credit Card Number",
                Evidence = "Potential credit card number detected",
                Severity = "Critical"
            });
        }
        
        return leaks;
    }
    
    private List<string> DetectTechnologyStack(HttpResponseMessage response, string content)
    {
        var technologies = new HashSet<string>();
        
        // Check headers
        if (response.Headers.TryGetValues("Server", out var serverValues))
        {
            technologies.Add($"Server: {serverValues.FirstOrDefault()}");
        }
        
        if (response.Headers.TryGetValues("X-Powered-By", out var poweredByValues))
        {
            technologies.Add($"Powered By: {poweredByValues.FirstOrDefault()}");
        }
        
        if (response.Headers.TryGetValues("X-AspNet-Version", out var aspNetValues))
        {
            technologies.Add($"ASP.NET: {aspNetValues.FirstOrDefault()}");
        }
        
        // Check content patterns
        var techPatterns = new Dictionary<string, string>
        {
            ["jQuery"] = @"jquery[\-\.][\d\.]+",
            ["React"] = @"react[\-\.][\d\.]+|_react|React\.version",
            ["Angular"] = @"angular[\-\.][\d\.]+|ng-version",
            ["Vue.js"] = @"vue[\-\.][\d\.]+|Vue\.version",
            ["Bootstrap"] = @"bootstrap[\-\.][\d\.]+",
            ["WordPress"] = @"wp-content|wp-includes|wordpress",
            ["Drupal"] = @"drupal|sites/all|sites/default",
            ["Laravel"] = @"laravel_session|laravel",
            ["Django"] = @"django|csrfmiddlewaretoken",
            ["Express"] = @"express|X-Powered-By.*Express",
            ["Spring"] = @"springframework|spring-boot"
        };
        
        foreach (var tech in techPatterns)
        {
            if (Regex.IsMatch(content, tech.Value, RegexOptions.IgnoreCase) ||
                response.Headers.ToString().Contains(tech.Key, StringComparison.OrdinalIgnoreCase))
            {
                technologies.Add(tech.Key);
            }
        }
        
        return technologies.ToList();
    }
    
    private List<string> DetectSecurityIndicators(HttpResponseMessage response, string content)
    {
        var indicators = new List<string>();
        
        // Check for security headers
        var securityHeaders = new[] 
        {
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-XSS-Protection"
        };
        
        foreach (var header in securityHeaders)
        {
            if (!response.Headers.Contains(header))
            {
                indicators.Add($"Missing security header: {header}");
            }
        }
        
        // Check for common security issues in content
        if (content.Contains("eval(", StringComparison.OrdinalIgnoreCase))
        {
            indicators.Add("Dangerous eval() usage detected");
        }
        
        if (content.Contains("document.write", StringComparison.OrdinalIgnoreCase))
        {
            indicators.Add("Dangerous document.write usage detected");
        }
        
        if (Regex.IsMatch(content, @"<script[^>]*src=[""']https?://", RegexOptions.IgnoreCase))
        {
            indicators.Add("External scripts loaded over HTTP/HTTPS");
        }
        
        return indicators;
    }
    
    private List<FormInfo> ExtractForms(string content)
    {
        var forms = new List<FormInfo>();
        var formPattern = @"<form[^>]*>(.*?)</form>";
        var matches = Regex.Matches(content, formPattern, RegexOptions.IgnoreCase | RegexOptions.Singleline);
        
        foreach (Match match in matches)
        {
            var form = new FormInfo();
            
            // Extract action
            var actionMatch = Regex.Match(match.Value, @"action=[""']([^""']+)[""']", RegexOptions.IgnoreCase);
            if (actionMatch.Success)
            {
                form.Action = actionMatch.Groups[1].Value;
            }
            
            // Extract method
            var methodMatch = Regex.Match(match.Value, @"method=[""']([^""']+)[""']", RegexOptions.IgnoreCase);
            form.Method = methodMatch.Success ? methodMatch.Groups[1].Value : "GET";
            
            // Extract inputs
            var inputPattern = @"<input[^>]*>";
            var inputMatches = Regex.Matches(match.Value, inputPattern, RegexOptions.IgnoreCase);
            
            foreach (Match inputMatch in inputMatches)
            {
                var nameMatch = Regex.Match(inputMatch.Value, @"name=[""']([^""']+)[""']", RegexOptions.IgnoreCase);
                var typeMatch = Regex.Match(inputMatch.Value, @"type=[""']([^""']+)[""']", RegexOptions.IgnoreCase);
                
                if (nameMatch.Success)
                {
                    form.Inputs.Add(new InputInfo
                    {
                        Name = nameMatch.Groups[1].Value,
                        Type = typeMatch.Success ? typeMatch.Groups[1].Value : "text"
                    });
                }
            }
            
            forms.Add(form);
        }
        
        return forms;
    }
    
    private List<string> ExtractLinks(string content)
    {
        var links = new HashSet<string>();
        
        // Extract href links
        var hrefPattern = @"href=[""']([^""']+)[""']";
        var hrefMatches = Regex.Matches(content, hrefPattern, RegexOptions.IgnoreCase);
        
        foreach (Match match in hrefMatches)
        {
            var link = match.Groups[1].Value;
            if (!link.StartsWith("#") && !link.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase))
            {
                links.Add(link);
            }
        }
        
        // Extract src links
        var srcPattern = @"src=[""']([^""']+)[""']";
        var srcMatches = Regex.Matches(content, srcPattern, RegexOptions.IgnoreCase);
        
        foreach (Match match in srcMatches)
        {
            links.Add(match.Groups[1].Value);
        }
        
        return links.ToList();
    }
    
    private bool IsJsonContent(string contentType)
    {
        return contentType.Contains("json", StringComparison.OrdinalIgnoreCase);
    }
    
    private bool IsHtmlContent(string contentType)
    {
        return contentType.Contains("html", StringComparison.OrdinalIgnoreCase);
    }
}

public class ResponseAnalysis
{
    public HttpStatusCode StatusCode { get; set; }
    public Dictionary<string, List<string>> Headers { get; set; } = new();
    public int ContentLength { get; set; }
    public string ContentType { get; set; } = string.Empty;
    public DateTime ResponseTime { get; set; }
    public List<DetectedError> DetectedErrors { get; set; } = new();
    public List<SensitiveDataLeak> SensitiveData { get; set; } = new();
    public List<string> TechnologyStack { get; set; } = new();
    public List<string> SecurityIndicators { get; set; } = new();
    public bool IsValidJson { get; set; }
    public JsonElement? JsonStructure { get; set; }
    public List<FormInfo> Forms { get; set; } = new();
    public List<string> Links { get; set; } = new();
}

public class DetectedError
{
    public ErrorType Type { get; set; }
    public string Description { get; set; } = string.Empty;
    public string Evidence { get; set; } = string.Empty;
    public int Position { get; set; }
}

public class SensitiveDataLeak
{
    public string Type { get; set; } = string.Empty;
    public string Evidence { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
}

public class FormInfo
{
    public string Action { get; set; } = string.Empty;
    public string Method { get; set; } = "GET";
    public List<InputInfo> Inputs { get; set; } = new();
}

public class InputInfo
{
    public string Name { get; set; } = string.Empty;
    public string Type { get; set; } = "text";
}

public class ErrorPattern
{
    public string Description { get; }
    public string Pattern { get; }
    public ErrorType Type { get; }
    
    public ErrorPattern(string description, string pattern, ErrorType type)
    {
        Description = description;
        Pattern = pattern;
        Type = type;
    }
}

public enum ErrorType
{
    SqlError,
    ApplicationError,
    ServerError,
    PathDisclosure,
    ConfigurationError
}