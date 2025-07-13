using VaultScope.Core.Interfaces;
using System.Text.RegularExpressions;

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
    
    private static readonly HashSet<int> DangerousPorts = new()
    {
        22,    // SSH
        23,    // Telnet
        25,    // SMTP
        53,    // DNS
        110,   // POP3
        143,   // IMAP
        161,   // SNMP
        389,   // LDAP
        445,   // SMB
        993,   // IMAPS
        995,   // POP3S
        1433,  // SQL Server
        1521,  // Oracle
        3306,  // MySQL
        3389,  // RDP
        5432,  // PostgreSQL
        5984,  // CouchDB
        6379,  // Redis
        9200,  // Elasticsearch
        27017  // MongoDB
    };
    
    private static readonly Regex SuspiciousPatterns = new(
        @"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\\|javascript:|data:|file:|ftp:|ldap:|dict:|gopher:|jar:|netdoc:|mailto:|news:|imap:|telnet:)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled
    );
    
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
        
        // Check for suspicious patterns before parsing
        if (SuspiciousPatterns.IsMatch(url))
        {
            return ValidationResult.Failure("URL contains suspicious patterns that could indicate an attack");
        }
        
        // Normalize URL to prevent bypass attempts
        url = url.Trim().ToLowerInvariant();
        
        // Check URL length to prevent DoS
        if (url.Length > 2048)
        {
            return ValidationResult.Failure("URL is too long (maximum 2048 characters)");
        }
        
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return ValidationResult.Failure("Invalid URL format");
        }
        
        if (!AllowedSchemes.Contains(uri.Scheme))
        {
            return ValidationResult.Failure($"Unsupported scheme: {uri.Scheme}. Only HTTP and HTTPS are allowed");
        }
        
        // Check for dangerous ports
        if (uri.Port != -1 && DangerousPorts.Contains(uri.Port))
        {
            return ValidationResult.Failure($"Port {uri.Port} is not allowed for security reasons");
        }
        
        // Validate port range
        if (uri.Port != -1 && (uri.Port < 1 || uri.Port > 65535))
        {
            return ValidationResult.Failure("Invalid port number");
        }
        
        var isLocalhost = IsLocalhostUri(uri);
        
        if (!isLocalhost)
        {
            return ValidationResult.Failure("Only localhost URLs are allowed for security reasons");
        }
        
        // Additional checks for localhost URLs
        if (uri.UserInfo.Length > 0)
        {
            return ValidationResult.Failure("URLs with user information are not allowed");
        }
        
        // Check for encoded characters that might bypass validation
        if (uri.AbsoluteUri.Contains("%") && !IsValidEncoding(uri.AbsoluteUri))
        {
            return ValidationResult.Failure("Invalid URL encoding detected");
        }
        
        return ValidationResult.Success(uri, isLocalhost);
    }
    
    private static bool IsValidEncoding(string url)
    {
        try
        {
            // Decode the URL and check if it contains suspicious patterns
            var decoded = Uri.UnescapeDataString(url);
            
            // Check for double encoding attempts
            if (decoded.Contains("%") && decoded != url)
            {
                var doubleDecoded = Uri.UnescapeDataString(decoded);
                if (SuspiciousPatterns.IsMatch(doubleDecoded))
                {
                    return false;
                }
            }
            
            return !SuspiciousPatterns.IsMatch(decoded);
        }
        catch
        {
            return false;
        }
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