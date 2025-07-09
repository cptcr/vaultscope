package dev.cptcr.vaultscope.security;

import dev.cptcr.vaultscope.util.Logger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Comprehensive security manager for VaultScope
 * Handles encryption, validation, and security monitoring
 */
public class SecurityManager {
    
    private static final Logger logger = Logger.getInstance();
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String HASH_ALGORITHM = "SHA-256";
    
    // Rate limiting and security monitoring
    private final ConcurrentHashMap<String, AtomicInteger> attemptCounts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> lastAttemptTime = new ConcurrentHashMap<>();
    private final int MAX_ATTEMPTS = 10;
    private final long RATE_LIMIT_WINDOW = 300000; // 5 minutes
    
    // Security configuration
    private final boolean enforceSecurityPolicies;
    private final String applicationSecret;
    
    public SecurityManager() {
        this.enforceSecurityPolicies = true;
        this.applicationSecret = generateSecureSecret();
        
        logger.security("SecurityManager", "Security manager initialized with enhanced protection");
        
        // Initialize security monitoring
        startSecurityMonitoring();
    }
    
    /**
     * Generate a secure random secret for application use
     */
    private String generateSecureSecret() {
        byte[] secretBytes = new byte[32];
        secureRandom.nextBytes(secretBytes);
        return Base64.getEncoder().encodeToString(secretBytes);
    }
    
    /**
     * Validate that a target URL is safe for testing
     */
    public SecurityValidationResult validateTargetUrl(String url) {
        if (url == null || url.trim().isEmpty()) {
            return SecurityValidationResult.failure("URL cannot be empty");
        }
        
        String normalizedUrl = url.trim().toLowerCase();
        
        // Check rate limiting
        if (isRateLimited("url_validation")) {
            logger.security("SecurityManager", "Rate limit exceeded for URL validation");
            return SecurityValidationResult.failure("Rate limit exceeded. Please wait before trying again.");
        }
        
        // Ensure localhost/private network only
        if (!isLocalhostOrPrivateNetwork(normalizedUrl)) {
            logger.security("SecurityManager", "Blocked non-localhost URL attempt: " + url);
            return SecurityValidationResult.failure("Only localhost and private network URLs are allowed for security reasons");
        }
        
        // Check for suspicious patterns
        if (containsSuspiciousPatterns(normalizedUrl)) {
            logger.security("SecurityManager", "Suspicious URL pattern detected: " + url);
            return SecurityValidationResult.failure("URL contains suspicious patterns");
        }
        
        // Validate URL structure
        if (!isValidUrlStructure(normalizedUrl)) {
            return SecurityValidationResult.failure("Invalid URL structure");
        }
        
        logger.security("SecurityManager", "URL validation successful: " + url);
        return SecurityValidationResult.success("URL is safe for testing");
    }
    
    /**
     * Secure data hashing for sensitive information
     */
    public String secureHash(String data) {
        if (data == null) {
            return null;
        }
        
        try {
            MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
            byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            logger.error("SecurityManager", "Failed to hash data", e.getMessage());
            return null;
        }
    }
    
    /**
     * Generate HMAC for data integrity verification
     */
    public String generateHMAC(String data) {
        if (data == null) {
            return null;
        }
        
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            SecretKeySpec secretKey = new SecretKeySpec(
                applicationSecret.getBytes(StandardCharsets.UTF_8), 
                HMAC_ALGORITHM
            );
            mac.init(secretKey);
            
            byte[] hmac = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hmac);
        } catch (Exception e) {
            logger.error("SecurityManager", "Failed to generate HMAC", e.getMessage());
            return null;
        }
    }
    
    /**
     * Verify HMAC for data integrity
     */
    public boolean verifyHMAC(String data, String expectedHMAC) {
        String calculatedHMAC = generateHMAC(data);
        return calculatedHMAC != null && calculatedHMAC.equals(expectedHMAC);
    }
    
    /**
     * Sanitize user input to prevent injection attacks
     */
    public String sanitizeInput(String input) {
        if (input == null) {
            return null;
        }
        
        // Remove potentially dangerous characters
        String sanitized = input
            .replaceAll("[<>\"'&]", "") // Remove HTML/XML characters
            .replaceAll("[\r\n\t]", " ") // Replace line breaks with spaces
            .replaceAll("\\s+", " ") // Normalize whitespace
            .trim();
        
        // Limit length to prevent DoS
        if (sanitized.length() > 1000) {
            sanitized = sanitized.substring(0, 1000);
        }
        
        return sanitized;
    }
    
    /**
     * Validate authentication credentials
     */
    public SecurityValidationResult validateCredentials(String type, String... credentials) {
        if (isRateLimited("auth_validation")) {
            logger.security("SecurityManager", "Rate limit exceeded for credential validation");
            return SecurityValidationResult.failure("Rate limit exceeded");
        }
        
        switch (type.toLowerCase()) {
            case "api_key":
                return validateApiKey(credentials[0]);
            case "jwt":
                return validateJWT(credentials[0]);
            case "basic":
                return validateBasicAuth(credentials[0], credentials[1]);
            default:
                return SecurityValidationResult.failure("Unknown authentication type");
        }
    }
    
    /**
     * Check if an action is rate limited
     */
    private boolean isRateLimited(String action) {
        long currentTime = System.currentTimeMillis();
        AtomicInteger attempts = attemptCounts.computeIfAbsent(action, k -> new AtomicInteger(0));
        Long lastTime = lastAttemptTime.get(action);
        
        if (lastTime == null || (currentTime - lastTime) > RATE_LIMIT_WINDOW) {
            // Reset window
            attempts.set(1);
            lastAttemptTime.put(action, currentTime);
            return false;
        }
        
        int currentAttempts = attempts.incrementAndGet();
        if (currentAttempts > MAX_ATTEMPTS) {
            logger.security("SecurityManager", "Rate limit exceeded for action: " + action);
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if URL is localhost or private network
     */
    private boolean isLocalhostOrPrivateNetwork(String url) {
        // Remove protocol if present
        String host = url.replaceAll("^https?://", "");
        
        // Extract host part
        if (host.contains("/")) {
            host = host.substring(0, host.indexOf("/"));
        }
        if (host.contains(":")) {
            host = host.substring(0, host.indexOf(":"));
        }
        
        // Check localhost patterns
        if (host.equals("localhost") || host.equals("127.0.0.1") || 
            host.equals("::1") || host.equals("0.0.0.0")) {
            return true;
        }
        
        // Check private network ranges
        if (host.startsWith("192.168.") || host.startsWith("10.") || 
            host.startsWith("172.16.") || host.startsWith("172.17.") ||
            host.startsWith("172.18.") || host.startsWith("172.19.") ||
            host.startsWith("172.20.") || host.startsWith("172.21.") ||
            host.startsWith("172.22.") || host.startsWith("172.23.") ||
            host.startsWith("172.24.") || host.startsWith("172.25.") ||
            host.startsWith("172.26.") || host.startsWith("172.27.") ||
            host.startsWith("172.28.") || host.startsWith("172.29.") ||
            host.startsWith("172.30.") || host.startsWith("172.31.")) {
            return true;
        }
        
        // Check IPv6 private ranges
        if (host.startsWith("fd") || host.startsWith("fe80:")) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Check for suspicious URL patterns
     */
    private boolean containsSuspiciousPatterns(String url) {
        String[] suspiciousPatterns = {
            "../", "..\\", "%2e%2e", "%2f", "%5c",
            "javascript:", "data:", "vbscript:",
            "<script", "</script", "onload=", "onerror=",
            "eval(", "exec(", "system(", "cmd(",
            "file://", "ftp://", "ldap://", "gopher://"
        };
        
        for (String pattern : suspiciousPatterns) {
            if (url.contains(pattern)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Validate URL structure
     */
    private boolean isValidUrlStructure(String url) {
        // Basic URL validation
        if (url.length() > 2048) { // RFC 2616 recommends max 2048 chars
            return false;
        }
        
        // Check for valid characters
        if (!url.matches("^[a-zA-Z0-9._~:/?#\\[\\]@!$&'()*+,;=-]+$")) {
            return false;
        }
        
        return true;
    }
    
    /**
     * Validate API key
     */
    private SecurityValidationResult validateApiKey(String apiKey) {
        if (apiKey == null || apiKey.trim().isEmpty()) {
            return SecurityValidationResult.failure("API key cannot be empty");
        }
        
        if (apiKey.length() < 8) {
            return SecurityValidationResult.failure("API key too short");
        }
        
        if (apiKey.length() > 512) {
            return SecurityValidationResult.failure("API key too long");
        }
        
        // Check for common weak keys
        String[] weakKeys = {"test", "admin", "password", "key", "secret", "token"};
        for (String weak : weakKeys) {
            if (apiKey.toLowerCase().contains(weak)) {
                return SecurityValidationResult.failure("API key appears to be weak or default");
            }
        }
        
        return SecurityValidationResult.success("API key format is valid");
    }
    
    /**
     * Validate JWT token
     */
    private SecurityValidationResult validateJWT(String jwt) {
        if (jwt == null || jwt.trim().isEmpty()) {
            return SecurityValidationResult.failure("JWT cannot be empty");
        }
        
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            return SecurityValidationResult.failure("Invalid JWT format");
        }
        
        // Basic format validation
        for (String part : parts) {
            if (part.isEmpty()) {
                return SecurityValidationResult.failure("JWT contains empty parts");
            }
        }
        
        return SecurityValidationResult.success("JWT format is valid");
    }
    
    /**
     * Validate basic authentication
     */
    private SecurityValidationResult validateBasicAuth(String username, String password) {
        if (username == null || username.trim().isEmpty()) {
            return SecurityValidationResult.failure("Username cannot be empty");
        }
        
        if (password == null || password.trim().isEmpty()) {
            return SecurityValidationResult.failure("Password cannot be empty");
        }
        
        // Check for common weak combinations
        String user = username.toLowerCase();
        String pass = password.toLowerCase();
        
        if ((user.equals("admin") && pass.equals("admin")) ||
            (user.equals("test") && pass.equals("test")) ||
            (user.equals("user") && pass.equals("password"))) {
            return SecurityValidationResult.failure("Weak username/password combination");
        }
        
        return SecurityValidationResult.success("Basic auth credentials are valid");
    }
    
    /**
     * Start security monitoring
     */
    private void startSecurityMonitoring() {
        Thread securityMonitor = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(60000); // Check every minute
                    
                    // Clean up old rate limit entries
                    long currentTime = System.currentTimeMillis();
                    lastAttemptTime.entrySet().removeIf(entry -> 
                        (currentTime - entry.getValue()) > RATE_LIMIT_WINDOW);
                    
                    // Log security statistics
                    if (attemptCounts.size() > 0) {
                        logger.security("SecurityManager", 
                            "Security monitoring active. Tracked actions: " + attemptCounts.size());
                    }
                    
                } catch (InterruptedException e) {
                    logger.warning("SecurityManager", "Security monitoring interrupted");
                    break;
                }
            }
        });
        
        securityMonitor.setDaemon(true);
        securityMonitor.setName("VaultScope-SecurityMonitor");
        securityMonitor.start();
    }
    
    /**
     * Security validation result
     */
    public static class SecurityValidationResult {
        private final boolean valid;
        private final String message;
        
        private SecurityValidationResult(boolean valid, String message) {
            this.valid = valid;
            this.message = message;
        }
        
        public static SecurityValidationResult success(String message) {
            return new SecurityValidationResult(true, message);
        }
        
        public static SecurityValidationResult failure(String message) {
            return new SecurityValidationResult(false, message);
        }
        
        public boolean isValid() {
            return valid;
        }
        
        public String getMessage() {
            return message;
        }
    }
}