namespace VaultScope.Core.Constants;

public static class SecurityHeaders
{
    public static readonly Dictionary<string, string> RequiredHeaders = new()
    {
        ["X-Content-Type-Options"] = "nosniff",
        ["X-Frame-Options"] = "DENY",
        ["X-XSS-Protection"] = "1; mode=block",
        ["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains",
        ["Content-Security-Policy"] = "default-src 'self'",
        ["Referrer-Policy"] = "strict-origin-when-cross-origin",
        ["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    };
    
    public static readonly Dictionary<string, string> HeaderDescriptions = new()
    {
        ["X-Content-Type-Options"] = "Prevents MIME type sniffing",
        ["X-Frame-Options"] = "Prevents clickjacking attacks",
        ["X-XSS-Protection"] = "Enables XSS filtering in browsers",
        ["Strict-Transport-Security"] = "Forces HTTPS connections",
        ["Content-Security-Policy"] = "Controls resource loading",
        ["Referrer-Policy"] = "Controls referrer information",
        ["Permissions-Policy"] = "Controls browser features and APIs",
        ["X-Permitted-Cross-Domain-Policies"] = "Controls cross-domain policies",
        ["Clear-Site-Data"] = "Clears browsing data",
        ["Cross-Origin-Embedder-Policy"] = "Controls cross-origin embedding",
        ["Cross-Origin-Opener-Policy"] = "Controls cross-origin window access",
        ["Cross-Origin-Resource-Policy"] = "Controls cross-origin resource sharing"
    };
    
    public static readonly List<string> DeprecatedHeaders = new()
    {
        "X-XSS-Protection",
        "Public-Key-Pins",
        "Expect-CT"
    };
}