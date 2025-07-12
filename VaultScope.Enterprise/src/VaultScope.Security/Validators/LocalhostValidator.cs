using VaultScope.Core.Interfaces;

namespace VaultScope.Security.Validators;

public class LocalhostValidator : IUrlValidator
{
    private static readonly HashSet<string> LocalhostNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "localhost",
        "127.0.0.1",
        "::1",
        "[::1]",
        "0.0.0.0"
    };
    
    private static readonly HashSet<string> AllowedSchemes = new(StringComparer.OrdinalIgnoreCase)
    {
        "http",
        "https"
    };
    
    public bool IsValid(string url)
    {
        return Validate(url).IsValid;
    }
    
    public bool IsLocalhost(string url)
    {
        var result = Validate(url);
        return result.IsValid && result.IsLocalhost;
    }
    
    public ValidationResult Validate(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return ValidationResult.Failure("URL cannot be empty");
        }
        
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return ValidationResult.Failure("Invalid URL format");
        }
        
        if (!AllowedSchemes.Contains(uri.Scheme))
        {
            return ValidationResult.Failure($"Unsupported scheme: {uri.Scheme}. Only HTTP and HTTPS are allowed");
        }
        
        var isLocalhost = IsLocalhostUri(uri);
        
        if (!isLocalhost)
        {
            return ValidationResult.Failure("Only localhost URLs are allowed for security reasons");
        }
        
        return ValidationResult.Success(uri, isLocalhost);
    }
    
    private static bool IsLocalhostUri(Uri uri)
    {
        if (LocalhostNames.Contains(uri.Host))
        {
            return true;
        }
        
        if (uri.HostNameType == UriHostNameType.IPv4 || uri.HostNameType == UriHostNameType.IPv6)
        {
            try
            {
                var address = System.Net.IPAddress.Parse(uri.Host);
                return System.Net.IPAddress.IsLoopback(address);
            }
            catch
            {
                return false;
            }
        }
        
        if (uri.Host.EndsWith(".local", StringComparison.OrdinalIgnoreCase) ||
            uri.Host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        
        return false;
    }
}