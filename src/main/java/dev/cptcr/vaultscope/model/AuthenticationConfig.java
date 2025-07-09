package dev.cptcr.vaultscope.model;

import java.util.Map;
import java.util.HashMap;

public class AuthenticationConfig {
    
    public enum AuthType {
        NONE, BASIC, BEARER, JWT, API_KEY, OAUTH2, CUSTOM
    }
    
    private AuthType authType;
    private String username;
    private String password;
    private String token;
    private String apiKey;
    private String apiKeyHeader;
    private String jwtSecret;
    private String clientId;
    private String clientSecret;
    private String authorizationUrl;
    private String tokenUrl;
    private String scope;
    private Map<String, String> customHeaders;
    private boolean testWeakSecrets;
    private boolean testAlgorithmConfusion;
    private boolean testTokenExpiration;
    private boolean testSessionFixation;
    private boolean testPrivilegeEscalation;
    
    public AuthenticationConfig() {
        this.authType = AuthType.NONE;
        this.customHeaders = new HashMap<>();
        this.testWeakSecrets = true;
        this.testAlgorithmConfusion = true;
        this.testTokenExpiration = true;
        this.testSessionFixation = true;
        this.testPrivilegeEscalation = true;
    }
    
    public AuthType getAuthType() {
        return authType;
    }
    
    public void setAuthType(AuthType authType) {
        this.authType = authType;
    }
    
    public String getUsername() {
        return username;
    }
    
    public void setUsername(String username) {
        this.username = username;
    }
    
    public String getPassword() {
        return password;
    }
    
    public void setPassword(String password) {
        this.password = password;
    }
    
    public String getToken() {
        return token;
    }
    
    public void setToken(String token) {
        this.token = token;
    }
    
    public String getApiKey() {
        return apiKey;
    }
    
    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }
    
    public String getApiKeyHeader() {
        return apiKeyHeader != null ? apiKeyHeader : "X-API-Key";
    }
    
    public void setApiKeyHeader(String apiKeyHeader) {
        this.apiKeyHeader = apiKeyHeader;
    }
    
    public String getJwtSecret() {
        return jwtSecret;
    }
    
    public void setJwtSecret(String jwtSecret) {
        this.jwtSecret = jwtSecret;
    }
    
    public String getClientId() {
        return clientId;
    }
    
    public void setClientId(String clientId) {
        this.clientId = clientId;
    }
    
    public String getClientSecret() {
        return clientSecret;
    }
    
    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }
    
    public String getAuthorizationUrl() {
        return authorizationUrl;
    }
    
    public void setAuthorizationUrl(String authorizationUrl) {
        this.authorizationUrl = authorizationUrl;
    }
    
    public String getTokenUrl() {
        return tokenUrl;
    }
    
    public void setTokenUrl(String tokenUrl) {
        this.tokenUrl = tokenUrl;
    }
    
    public String getScope() {
        return scope;
    }
    
    public void setScope(String scope) {
        this.scope = scope;
    }
    
    public Map<String, String> getCustomHeaders() {
        return customHeaders;
    }
    
    public void setCustomHeaders(Map<String, String> customHeaders) {
        this.customHeaders = customHeaders;
    }
    
    public boolean isTestWeakSecrets() {
        return testWeakSecrets;
    }
    
    public void setTestWeakSecrets(boolean testWeakSecrets) {
        this.testWeakSecrets = testWeakSecrets;
    }
    
    public boolean isTestAlgorithmConfusion() {
        return testAlgorithmConfusion;
    }
    
    public void setTestAlgorithmConfusion(boolean testAlgorithmConfusion) {
        this.testAlgorithmConfusion = testAlgorithmConfusion;
    }
    
    public boolean isTestTokenExpiration() {
        return testTokenExpiration;
    }
    
    public void setTestTokenExpiration(boolean testTokenExpiration) {
        this.testTokenExpiration = testTokenExpiration;
    }
    
    public boolean isTestSessionFixation() {
        return testSessionFixation;
    }
    
    public void setTestSessionFixation(boolean testSessionFixation) {
        this.testSessionFixation = testSessionFixation;
    }
    
    public boolean isTestPrivilegeEscalation() {
        return testPrivilegeEscalation;
    }
    
    public void setTestPrivilegeEscalation(boolean testPrivilegeEscalation) {
        this.testPrivilegeEscalation = testPrivilegeEscalation;
    }
    
    public boolean hasAuthentication() {
        return authType != AuthType.NONE;
    }
    
    public String getAuthorizationHeader() {
        return switch (authType) {
            case BASIC -> "Basic " + java.util.Base64.getEncoder()
                .encodeToString((username + ":" + password).getBytes());
            case BEARER, JWT -> "Bearer " + token;
            default -> null;
        };
    }
}