namespace VaultScope.Core.Models;

public class AuthenticationResult
{
    public bool IsAuthenticated { get; set; }
    
    public AuthenticationType Type { get; set; }
    
    public Dictionary<string, string> Headers { get; set; } = new();
    
    public Dictionary<string, string> Cookies { get; set; } = new();
    
    public string? Token { get; set; }
    
    public DateTime? ExpiresAt { get; set; }
    
    public List<string> Scopes { get; set; } = new();
    
    public string? RefreshToken { get; set; }
    
    public Dictionary<string, object> AdditionalData { get; set; } = new();
}

public enum AuthenticationType
{
    None,
    Basic,
    Bearer,
    ApiKey,
    OAuth2,
    Cookie,
    Custom
}