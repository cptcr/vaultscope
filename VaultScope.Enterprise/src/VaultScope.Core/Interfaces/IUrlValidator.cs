namespace VaultScope.Core.Interfaces;

public interface IUrlValidator
{
    bool IsValid(string url);
    
    bool IsLocalhost(string url);
    
    ValidationResult Validate(string url);
}

public class ValidationResult
{
    public bool IsValid { get; set; }
    
    public bool IsLocalhost { get; set; }
    
    public string? ErrorMessage { get; set; }
    
    public Uri? ParsedUri { get; set; }
    
    public static ValidationResult Success(Uri uri, bool isLocalhost) => new()
    {
        IsValid = true,
        IsLocalhost = isLocalhost,
        ParsedUri = uri
    };
    
    public static ValidationResult Failure(string error) => new()
    {
        IsValid = false,
        ErrorMessage = error
    };
}