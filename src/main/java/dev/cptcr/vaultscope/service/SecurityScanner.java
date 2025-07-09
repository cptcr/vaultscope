package dev.cptcr.vaultscope.service;

import dev.cptcr.vaultscope.model.SecurityResult;
import dev.cptcr.vaultscope.model.Vulnerability;
import org.apache.hc.client5.http.classic.methods.*;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.entity.UrlEncodedFormEntity;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicNameValuePair;
import org.apache.hc.core5.util.Timeout;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

public class SecurityScanner {

    private static final String[] SQL_INJECTION_PAYLOADS = {
        "' OR '1'='1", "' OR 1=1--", "'; DROP TABLE users--", 
        "' UNION SELECT NULL--", "1' AND SLEEP(5)--", "' OR '1'='1' /*"
    };

    private static final String[] NOSQL_INJECTION_PAYLOADS = {
        "[$ne]", "{\"$gt\":\"\"}", "true, $where: '1 == 1'",
        "', $where: '1 == 1", "1; return Math.PI"
    };

    private static final String[] PATH_TRAVERSAL_PAYLOADS = {
        "../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f", "....//....//....//etc/passwd"
    };

    private static final String[] XSS_PAYLOADS = {
        "<script>alert('XSS')</script>", "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>", "'\"><script>alert('XSS')</script>"
    };

    private static final String[] XXE_PAYLOADS = {
        "<?xml version=\"1.0\"?><!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><test>&xxe;</test>",
        "<?xml version=\"1.0\"?><!DOCTYPE test [<!ENTITY xxe SYSTEM \"http://localhost/test\">]><test>&xxe;</test>"
    };

    private UrlValidator urlValidator;

    public SecurityScanner() {
        this.urlValidator = new UrlValidator();
    }

    public SecurityResult performSecurityScan(String targetUrl, Consumer<String> logCallback, Consumer<Double> progressCallback) {
        String normalizedUrl = urlValidator.normalizeUrl(targetUrl);
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        logCallback.accept("Starting security scan for: " + normalizedUrl);
        progressCallback.accept(0.0);

        try (CloseableHttpClient httpClient = createHttpClient()) {
            
            testBasicConnectivity(httpClient, normalizedUrl, vulnerabilities, logCallback);
            progressCallback.accept(0.1);

            testSqlInjection(httpClient, normalizedUrl, vulnerabilities, logCallback);
            progressCallback.accept(0.2);

            testNoSqlInjection(httpClient, normalizedUrl, vulnerabilities, logCallback);
            progressCallback.accept(0.3);

            testPathTraversal(httpClient, normalizedUrl, vulnerabilities, logCallback);
            progressCallback.accept(0.4);

            testXssVulnerabilities(httpClient, normalizedUrl, vulnerabilities, logCallback);
            progressCallback.accept(0.5);

            testXxeVulnerabilities(httpClient, normalizedUrl, vulnerabilities, logCallback);
            progressCallback.accept(0.6);

            testHttpMethodOverride(httpClient, normalizedUrl, vulnerabilities, logCallback);
            progressCallback.accept(0.7);

            testHeaderInjection(httpClient, normalizedUrl, vulnerabilities, logCallback);
            progressCallback.accept(0.8);

            testAuthenticationBypass(httpClient, normalizedUrl, vulnerabilities, logCallback);
            progressCallback.accept(0.9);

            testRateLimiting(httpClient, normalizedUrl, vulnerabilities, logCallback);
            progressCallback.accept(1.0);

        } catch (Exception e) {
            logCallback.accept("Scan error: " + e.getMessage());
            vulnerabilities.add(createVulnerability("ERROR", "Scan Error", targetUrl, 
                "Failed to complete security scan", e.getMessage(), "Review connectivity and target availability"));
        }

        logCallback.accept("Scan completed. Found " + vulnerabilities.size() + " potential vulnerabilities.");
        
        int securityScore = calculateSecurityScore(vulnerabilities);
        return new SecurityResult(targetUrl, LocalDateTime.now(), vulnerabilities, securityScore);
    }

    private CloseableHttpClient createHttpClient() {
        RequestConfig config = RequestConfig.custom()
            .setConnectTimeout(Timeout.of(10, TimeUnit.SECONDS))
            .setResponseTimeout(Timeout.of(30, TimeUnit.SECONDS))
            .build();
        
        return HttpClients.custom()
            .setDefaultRequestConfig(config)
            .build();
    }

    private void testBasicConnectivity(CloseableHttpClient client, String url, List<Vulnerability> vulnerabilities, Consumer<String> logCallback) {
        try {
            HttpGet request = new HttpGet(url);
            logCallback.accept("Testing basic connectivity to " + url);
            
            try (CloseableHttpResponse response = client.execute(request)) {
                int statusCode = response.getCode();
                String responseBody = EntityUtils.toString(response.getEntity());
                
                logCallback.accept("GET " + url + " -> " + statusCode);
                
                if (responseBody.toLowerCase().contains("error") || responseBody.toLowerCase().contains("exception")) {
                    vulnerabilities.add(createVulnerability("MEDIUM", "Information Disclosure", url,
                        "Error information exposed in response", 
                        "Response contains error details that may reveal system information",
                        "Configure error handling to avoid exposing sensitive information"));
                }
                
                String serverHeader = response.getFirstHeader("Server") != null ? 
                    response.getFirstHeader("Server").getValue() : "";
                if (!serverHeader.isEmpty()) {
                    vulnerabilities.add(createVulnerability("LOW", "Information Disclosure", url,
                        "Server information disclosed", 
                        "Server header reveals: " + serverHeader,
                        "Remove or obfuscate server header information"));
                }
            }
        } catch (Exception e) {
            logCallback.accept("Basic connectivity test failed: " + e.getMessage());
        }
    }

    private void testSqlInjection(CloseableHttpClient client, String url, List<Vulnerability> vulnerabilities, Consumer<String> logCallback) {
        logCallback.accept("Testing SQL injection vulnerabilities...");
        
        for (String payload : SQL_INJECTION_PAYLOADS) {
            try {
                String testUrl = url + "?id=" + payload + "&username=" + payload;
                HttpGet request = new HttpGet(testUrl);
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    long responseTime = System.currentTimeMillis();
                    
                    logCallback.accept("SQL Test: " + payload + " -> " + response.getCode());
                    
                    if (responseBody.toLowerCase().contains("sql") || 
                        responseBody.toLowerCase().contains("mysql") ||
                        responseBody.toLowerCase().contains("oracle") ||
                        responseBody.toLowerCase().contains("postgresql") ||
                        response.getCode() == 500) {
                        
                        vulnerabilities.add(createVulnerability("CRITICAL", "SQL Injection", testUrl,
                            "Potential SQL injection vulnerability detected",
                            "Payload: " + payload + " caused suspicious response",
                            "Use parameterized queries and input validation"));
                    }
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                logCallback.accept("SQL injection test error: " + e.getMessage());
            }
        }
    }

    private void testNoSqlInjection(CloseableHttpClient client, String url, List<Vulnerability> vulnerabilities, Consumer<String> logCallback) {
        logCallback.accept("Testing NoSQL injection vulnerabilities...");
        
        for (String payload : NOSQL_INJECTION_PAYLOADS) {
            try {
                HttpPost request = new HttpPost(url);
                request.setHeader("Content-Type", "application/json");
                request.setEntity(new StringEntity("{\"query\":\"" + payload + "\"}"));
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    
                    logCallback.accept("NoSQL Test: " + payload + " -> " + response.getCode());
                    
                    if (responseBody.toLowerCase().contains("mongo") ||
                        responseBody.toLowerCase().contains("bson") ||
                        response.getCode() == 500) {
                        
                        vulnerabilities.add(createVulnerability("HIGH", "NoSQL Injection", url,
                            "Potential NoSQL injection vulnerability detected",
                            "Payload: " + payload + " caused suspicious response",
                            "Validate and sanitize all input data"));
                    }
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                logCallback.accept("NoSQL injection test error: " + e.getMessage());
            }
        }
    }

    private void testPathTraversal(CloseableHttpClient client, String url, List<Vulnerability> vulnerabilities, Consumer<String> logCallback) {
        logCallback.accept("Testing path traversal vulnerabilities...");
        
        for (String payload : PATH_TRAVERSAL_PAYLOADS) {
            try {
                String testUrl = url + "/file?path=" + payload;
                HttpGet request = new HttpGet(testUrl);
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    
                    logCallback.accept("Path Traversal Test: " + payload + " -> " + response.getCode());
                    
                    if (responseBody.contains("root:") || 
                        responseBody.contains("localhost") ||
                        responseBody.contains("admin") ||
                        (response.getCode() == 200 && responseBody.length() > 1000)) {
                        
                        vulnerabilities.add(createVulnerability("HIGH", "Path Traversal", testUrl,
                            "Potential path traversal vulnerability detected",
                            "Payload: " + payload + " may have accessed system files",
                            "Implement proper file access controls and input validation"));
                    }
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                logCallback.accept("Path traversal test error: " + e.getMessage());
            }
        }
    }

    private void testXssVulnerabilities(CloseableHttpClient client, String url, List<Vulnerability> vulnerabilities, Consumer<String> logCallback) {
        logCallback.accept("Testing XSS vulnerabilities...");
        
        for (String payload : XSS_PAYLOADS) {
            try {
                String testUrl = url + "?search=" + payload;
                HttpGet request = new HttpGet(testUrl);
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    
                    logCallback.accept("XSS Test: " + payload + " -> " + response.getCode());
                    
                    if (responseBody.contains(payload) || 
                        responseBody.contains("<script>") ||
                        responseBody.contains("javascript:")) {
                        
                        vulnerabilities.add(createVulnerability("HIGH", "Cross-Site Scripting", testUrl,
                            "Potential XSS vulnerability detected",
                            "Payload: " + payload + " was reflected in response",
                            "Implement output encoding and Content Security Policy"));
                    }
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                logCallback.accept("XSS test error: " + e.getMessage());
            }
        }
    }

    private void testXxeVulnerabilities(CloseableHttpClient client, String url, List<Vulnerability> vulnerabilities, Consumer<String> logCallback) {
        logCallback.accept("Testing XXE vulnerabilities...");
        
        for (String payload : XXE_PAYLOADS) {
            try {
                HttpPost request = new HttpPost(url);
                request.setHeader("Content-Type", "application/xml");
                request.setEntity(new StringEntity(payload));
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    
                    logCallback.accept("XXE Test -> " + response.getCode());
                    
                    if (responseBody.contains("root:") || 
                        responseBody.contains("passwd") ||
                        responseBody.contains("xml") && response.getCode() == 500) {
                        
                        vulnerabilities.add(createVulnerability("CRITICAL", "XML External Entity", url,
                            "Potential XXE vulnerability detected",
                            "XML parser may be processing external entities",
                            "Disable external entity processing in XML parsers"));
                    }
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                logCallback.accept("XXE test error: " + e.getMessage());
            }
        }
    }

    private void testHttpMethodOverride(CloseableHttpClient client, String url, List<Vulnerability> vulnerabilities, Consumer<String> logCallback) {
        logCallback.accept("Testing HTTP method override...");
        
        String[] methods = {"DELETE", "PUT", "PATCH", "TRACE", "OPTIONS"};
        
        for (String method : methods) {
            try {
                HttpUriRequestBase request;
                switch (method) {
                    case "DELETE" -> request = new HttpDelete(url);
                    case "PUT" -> request = new HttpPut(url);
                    case "PATCH" -> request = new HttpPatch(url);
                    case "TRACE" -> request = new HttpTrace(url);
                    case "OPTIONS" -> request = new HttpOptions(url);
                    default -> continue;
                }
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    logCallback.accept(method + " " + url + " -> " + response.getCode());
                    
                    if (response.getCode() == 200 || response.getCode() == 204) {
                        vulnerabilities.add(createVulnerability("MEDIUM", "HTTP Method Override", url,
                            "Dangerous HTTP method allowed",
                            method + " method returned successful response",
                            "Restrict allowed HTTP methods to only those required"));
                    }
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                logCallback.accept("HTTP method test error: " + e.getMessage());
            }
        }
    }

    private void testHeaderInjection(CloseableHttpClient client, String url, List<Vulnerability> vulnerabilities, Consumer<String> logCallback) {
        logCallback.accept("Testing header injection vulnerabilities...");
        
        try {
            HttpGet request = new HttpGet(url);
            request.setHeader("X-Forwarded-For", "127.0.0.1\r\nX-Injected: injected");
            request.setHeader("User-Agent", "VaultScope\r\nX-Injected: injected");
            
            try (CloseableHttpResponse response = client.execute(request)) {
                String responseHeaders = response.toString();
                
                logCallback.accept("Header Injection Test -> " + response.getCode());
                
                if (responseHeaders.contains("X-Injected")) {
                    vulnerabilities.add(createVulnerability("MEDIUM", "Header Injection", url,
                        "Header injection vulnerability detected",
                        "Application reflects injected headers",
                        "Validate and sanitize all header values"));
                }
            }
        } catch (Exception e) {
            logCallback.accept("Header injection test error: " + e.getMessage());
        }
    }

    private void testAuthenticationBypass(CloseableHttpClient client, String url, List<Vulnerability> vulnerabilities, Consumer<String> logCallback) {
        logCallback.accept("Testing authentication bypass...");
        
        String[] authBypassHeaders = {
            "X-Forwarded-User:admin",
            "X-Remote-User:administrator", 
            "X-Forwarded-For:127.0.0.1",
            "Authorization:Bearer fake-token"
        };
        
        for (String header : authBypassHeaders) {
            try {
                String[] parts = header.split(":", 2);
                HttpGet request = new HttpGet(url + "/admin");
                request.setHeader(parts[0], parts[1]);
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    logCallback.accept("Auth Bypass Test: " + header + " -> " + response.getCode());
                    
                    if (response.getCode() == 200) {
                        vulnerabilities.add(createVulnerability("CRITICAL", "Authentication Bypass", url,
                            "Authentication bypass detected",
                            "Header " + header + " granted access to protected resource",
                            "Implement proper authentication and authorization checks"));
                    }
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                logCallback.accept("Auth bypass test error: " + e.getMessage());
            }
        }
    }

    private void testRateLimiting(CloseableHttpClient client, String url, List<Vulnerability> vulnerabilities, Consumer<String> logCallback) {
        logCallback.accept("Testing rate limiting...");
        
        try {
            int successfulRequests = 0;
            for (int i = 0; i < 20; i++) {
                HttpGet request = new HttpGet(url);
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    if (response.getCode() == 200) {
                        successfulRequests++;
                    }
                }
                Thread.sleep(50);
            }
            
            logCallback.accept("Rate Limiting Test: " + successfulRequests + "/20 requests succeeded");
            
            if (successfulRequests >= 18) {
                vulnerabilities.add(createVulnerability("MEDIUM", "Missing Rate Limiting", url,
                    "No rate limiting detected",
                    "Multiple rapid requests succeeded without throttling",
                    "Implement rate limiting to prevent abuse"));
            }
        } catch (Exception e) {
            logCallback.accept("Rate limiting test error: " + e.getMessage());
        }
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
        return vuln;
    }

    private int calculateSecurityScore(List<Vulnerability> vulnerabilities) {
        int score = 100;
        
        for (Vulnerability vuln : vulnerabilities) {
            switch (vuln.getSeverity()) {
                case "CRITICAL" -> score -= 25;
                case "HIGH" -> score -= 15;
                case "MEDIUM" -> score -= 8;
                case "LOW" -> score -= 3;
            }
        }
        
        return Math.max(0, score);
    }
}