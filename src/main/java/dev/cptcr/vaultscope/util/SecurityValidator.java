package dev.cptcr.vaultscope.util;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Pattern;

public class SecurityValidator {
    
    private static final Pattern LOCALHOST_PATTERN = Pattern.compile(
        "^(https?://)?(localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0|::1)(:[0-9]+)?(/.*)?$",
        Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern PRIVATE_IP_PATTERN = Pattern.compile(
        "^(https?://)?(10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|192\\.168\\.|169\\.254\\.|fd[0-9a-f]{2}:|fe80:)(.*)?$",
        Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern SECURE_HEADER_PATTERN = Pattern.compile(
        "^[a-zA-Z0-9\\-_]+$"
    );
    
    public static class ValidationResult {
        private final boolean valid;
        private final String message;
        private final Severity severity;
        
        public enum Severity {
            INFO, WARNING, ERROR, CRITICAL
        }
        
        public ValidationResult(boolean valid, String message, Severity severity) {
            this.valid = valid;
            this.message = message;
            this.severity = severity;
        }
        
        public boolean isValid() { return valid; }
        public String getMessage() { return message; }
        public Severity getSeverity() { return severity; }
    }
    
    public static ValidationResult validateTargetUrl(String url) {
        if (url == null || url.trim().isEmpty()) {
            return new ValidationResult(false, "Target URL cannot be empty", ValidationResult.Severity.ERROR);
        }
        
        try {
            String normalizedUrl = url.trim();
            if (!normalizedUrl.startsWith("http://") && !normalizedUrl.startsWith("https://")) {
                normalizedUrl = "http://" + normalizedUrl;
            }
            
            URI uri = new URI(normalizedUrl);
            
            // Check if it's localhost or private IP
            if (LOCALHOST_PATTERN.matcher(normalizedUrl).matches()) {
                return new ValidationResult(true, "✓ Safe localhost target", ValidationResult.Severity.INFO);
            }
            
            if (PRIVATE_IP_PATTERN.matcher(normalizedUrl).matches()) {
                return new ValidationResult(true, "✓ Safe private network target", ValidationResult.Severity.INFO);
            }
            
            // Block public IPs and domains
            return new ValidationResult(false, 
                "❌ BLOCKED: VaultScope only allows localhost and private network testing for security reasons", 
                ValidationResult.Severity.CRITICAL);
            
        } catch (URISyntaxException e) {
            return new ValidationResult(false, "Invalid URL format: " + e.getMessage(), ValidationResult.Severity.ERROR);
        }
    }
    
    public static ValidationResult validateApiKey(String apiKey) {
        if (apiKey == null || apiKey.trim().isEmpty()) {
            return new ValidationResult(false, "API key cannot be empty", ValidationResult.Severity.ERROR);
        }
        
        String key = apiKey.trim();
        
        // Check for common insecure patterns
        if (key.length() < 8) {
            return new ValidationResult(false, "API key too short (minimum 8 characters)", ValidationResult.Severity.ERROR);
        }
        
        if (key.equals("test") || key.equals("admin") || key.equals("password")) {
            return new ValidationResult(false, "API key uses common insecure value", ValidationResult.Severity.CRITICAL);
        }
        
        if (key.matches("^[0-9]+$")) {
            return new ValidationResult(false, "API key should not be numeric only", ValidationResult.Severity.WARNING);
        }
        
        return new ValidationResult(true, "✓ API key format appears valid", ValidationResult.Severity.INFO);
    }
    
    public static ValidationResult validateJWT(String jwt) {
        if (jwt == null || jwt.trim().isEmpty()) {
            return new ValidationResult(false, "JWT token cannot be empty", ValidationResult.Severity.ERROR);
        }
        
        String token = jwt.trim();
        
        // Basic JWT format validation
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return new ValidationResult(false, "Invalid JWT format (should have 3 parts)", ValidationResult.Severity.ERROR);
        }
        
        // Check for obvious test tokens
        if (token.contains("test") || token.contains("example") || token.contains("demo")) {
            return new ValidationResult(false, "JWT appears to be a test/demo token", ValidationResult.Severity.WARNING);
        }
        
        return new ValidationResult(true, "✓ JWT format appears valid", ValidationResult.Severity.INFO);
    }
    
    public static ValidationResult validateBasicAuth(String username, String password) {
        if (username == null || username.trim().isEmpty()) {
            return new ValidationResult(false, "Username cannot be empty", ValidationResult.Severity.ERROR);
        }
        
        if (password == null || password.trim().isEmpty()) {
            return new ValidationResult(false, "Password cannot be empty", ValidationResult.Severity.ERROR);
        }
        
        // Check for common insecure combinations
        String user = username.trim().toLowerCase();
        String pass = password.trim().toLowerCase();
        
        if ((user.equals("admin") && pass.equals("admin")) ||
            (user.equals("test") && pass.equals("test")) ||
            (user.equals("user") && pass.equals("password"))) {
            return new ValidationResult(false, "Insecure username/password combination detected", ValidationResult.Severity.CRITICAL);
        }
        
        if (password.length() < 6) {
            return new ValidationResult(false, "Password too short (minimum 6 characters)", ValidationResult.Severity.WARNING);
        }
        
        return new ValidationResult(true, "✓ Basic auth credentials appear valid", ValidationResult.Severity.INFO);
    }
    
    public static ValidationResult validateCustomHeader(String name, String value) {
        if (name == null || name.trim().isEmpty()) {
            return new ValidationResult(false, "Header name cannot be empty", ValidationResult.Severity.ERROR);
        }
        
        if (value == null || value.trim().isEmpty()) {
            return new ValidationResult(false, "Header value cannot be empty", ValidationResult.Severity.ERROR);
        }
        
        String headerName = name.trim();
        String headerValue = value.trim();
        
        // Validate header name format
        if (!SECURE_HEADER_PATTERN.matcher(headerName).matches()) {
            return new ValidationResult(false, "Invalid header name format", ValidationResult.Severity.ERROR);
        }
        
        // Check for dangerous headers
        String lowerName = headerName.toLowerCase();
        if (lowerName.equals("host") || lowerName.equals("origin") || lowerName.equals("referer")) {
            return new ValidationResult(false, "Dangerous header detected: " + headerName, ValidationResult.Severity.CRITICAL);
        }
        
        // Check for potential injection
        if (headerValue.contains("<script>") || headerValue.contains("javascript:") || 
            headerValue.contains("${") || headerValue.contains("{{")) {
            return new ValidationResult(false, "Potential injection detected in header value", ValidationResult.Severity.CRITICAL);
        }
        
        return new ValidationResult(true, "✓ Custom header appears safe", ValidationResult.Severity.INFO);
    }
    
    public static boolean isSecureConnection(String url) {
        return url != null && url.trim().toLowerCase().startsWith("https://");
    }
    
    public static boolean isLocalhostTarget(String url) {
        if (url == null) return false;
        return LOCALHOST_PATTERN.matcher(url.trim()).matches();
    }
    
    public static boolean isPrivateNetworkTarget(String url) {
        if (url == null) return false;
        return PRIVATE_IP_PATTERN.matcher(url.trim()).matches();
    }
}