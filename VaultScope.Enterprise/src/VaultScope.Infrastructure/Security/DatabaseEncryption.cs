using System.Security.Cryptography;
using System.Text;

namespace VaultScope.Infrastructure.Security;

public static class DatabaseEncryption
{
    private const string KeyStoreName = "VaultScope_DbKey";
    
    public static string GetOrCreateEncryptionKey()
    {
        // Try to get existing key from secure storage
        var existingKey = GetKeyFromSecureStorage();
        if (!string.IsNullOrEmpty(existingKey))
        {
            return existingKey;
        }
        
        // Generate new key if none exists
        var newKey = GenerateEncryptionKey();
        StoreKeySecurely(newKey);
        return newKey;
    }
    
    private static string GenerateEncryptionKey()
    {
        using var rng = RandomNumberGenerator.Create();
        var keyBytes = new byte[32]; // 256-bit key
        rng.GetBytes(keyBytes);
        return Convert.ToBase64String(keyBytes);
    }
    
    private static string? GetKeyFromSecureStorage()
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                return GetKeyFromWindowsCredentialManager();
            }
            else if (OperatingSystem.IsMacOS())
            {
                return GetKeyFromMacOSKeychain();
            }
            else if (OperatingSystem.IsLinux())
            {
                return GetKeyFromLinuxSecretService();
            }
            
            return null;
        }
        catch
        {
            return null;
        }
    }
    
    private static void StoreKeySecurely(string key)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                StoreKeyInWindowsCredentialManager(key);
            }
            else if (OperatingSystem.IsMacOS())
            {
                StoreKeyInMacOSKeychain(key);
            }
            else if (OperatingSystem.IsLinux())
            {
                StoreKeyInLinuxSecretService(key);
            }
        }
        catch
        {
            // Fallback to environment variable (less secure)
            Environment.SetEnvironmentVariable($"VAULTSCOPE_DB_KEY", key, EnvironmentVariableTarget.User);
        }
    }
    
    private static string? GetKeyFromWindowsCredentialManager()
    {
        // Simplified implementation - in production, use Windows Credential Manager API
        return Environment.GetEnvironmentVariable($"VAULTSCOPE_DB_KEY", EnvironmentVariableTarget.User);
    }
    
    private static void StoreKeyInWindowsCredentialManager(string key)
    {
        // Simplified implementation - in production, use Windows Credential Manager API
        Environment.SetEnvironmentVariable($"VAULTSCOPE_DB_KEY", key, EnvironmentVariableTarget.User);
    }
    
    private static string? GetKeyFromMacOSKeychain()
    {
        // Simplified implementation - in production, use macOS Keychain Services
        return Environment.GetEnvironmentVariable($"VAULTSCOPE_DB_KEY", EnvironmentVariableTarget.User);
    }
    
    private static void StoreKeyInMacOSKeychain(string key)
    {
        // Simplified implementation - in production, use macOS Keychain Services
        Environment.SetEnvironmentVariable($"VAULTSCOPE_DB_KEY", key, EnvironmentVariableTarget.User);
    }
    
    private static string? GetKeyFromLinuxSecretService()
    {
        // Simplified implementation - in production, use Secret Service API
        return Environment.GetEnvironmentVariable($"VAULTSCOPE_DB_KEY", EnvironmentVariableTarget.User);
    }
    
    private static void StoreKeyInLinuxSecretService(string key)
    {
        // Simplified implementation - in production, use Secret Service API
        Environment.SetEnvironmentVariable($"VAULTSCOPE_DB_KEY", key, EnvironmentVariableTarget.User);
    }
}