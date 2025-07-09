package dev.cptcr.vaultscope.service;

import dev.cptcr.vaultscope.model.SecurityResult;
import dev.cptcr.vaultscope.model.Vulnerability;
import org.apache.hc.client5.http.classic.methods.*;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.util.Timeout;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

public class SecurityScanner {

    private static final String[] SQL_INJECTION_PAYLOADS = {
        "' OR '1'='1", "' OR 1=1--", "'; DROP TABLE users--", 
        "' UNION SELECT NULL--", "1' AND SLEEP(5)--", "' OR '1'='1' /*",
        "admin'--", "admin' #", "admin'/*", "' or 1=1#",
        "' or 1=1--", ") or '1'='1--", ") or ('1'='1--"
    };

    private static final String[] NOSQL_INJECTION_PAYLOADS = {
        "[$ne]", "{\"$gt\":\"\"}", "true, $where: '1 == 1'",
        "', $where: '1 == 1", "1; return Math.PI", "{\"$where\":\"1==1\"}",
        "admin' || 'a'=='a", "1'||'1'=='1", "{$regex: \".*\"}"
    };

    private static final String[] PATH_TRAVERSAL_PAYLOADS = {
        "../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f", "....//....//....//etc/passwd",
        "..%252f..%252f..%252fetc%252fpasswd", "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
    };

    private static final String[] XSS_PAYLOADS = {
        "<script>alert('XSS')</script>", "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>", "'\"><script>alert('XSS')</script>",
        "<svg onload=alert('XSS')>", "<<SCRIPT>alert('XSS')//<</SCRIPT>",
        "<iframe src=javascript:alert('XSS')></iframe>"
    };

    private static final String[] XXE_PAYLOADS = {
        "<?xml version=\"1.0\"?><!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><test>&xxe;</test>",
        "<?xml version=\"1.0\"?><!DOCTYPE test [<!ENTITY xxe SYSTEM \"http://localhost/test\">]><test>&xxe;</test>",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><foo>&xxe;</foo>"
    };

    private UrlValidator urlValidator;

    public SecurityScanner() {
        this.urlValidator = new UrlValidator();
    }

    public SecurityResult performSecurityScan(String targetUrl, Consumer<String> logCallback, Consumer<Double> progressCallback) {
        String normalizedUrl = urlValidator.normalizeUrl(targetUrl);
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        long startTime = System.currentTimeMillis();
        
        logCallback.accept("🚀 Starting comprehensive security assessment");
        logCallback.accept("🎯 Target: " + normalizedUrl);
        logCallback.accept("⏰ Started: " + LocalDateTime.now());
        logCallback.accept("" + "=".repeat(60));
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
            logCallback.accept("❌ Scan error: " + e.getMessage());
        }

        long endTime = System.currentTimeMillis();
        long duration = endTime - startTime;
        
        logCallback.accept("" + "=".repeat(60));
        logCallback.accept(String.format("✅ Scan completed in %.2f seconds", duration / 1000.0));
        logCallback.accept(String.format("🔍 Found %d potential security vulnerabilities", vulnerabilities.size()));
        
        int securityScore = calculateSecurityScore(vulnerabilities);
        SecurityResult result = new SecurityResult(targetUrl, LocalDateTime.now(), vulnerabilities, securityScore);
        result.setScanDuration(String.format("%.2f seconds", duration / 1000.0));
        return result;
    }

    private CloseableHttpClient createHttpClient() {
        RequestConfig config = RequestConfig.custom()
            .setConnectTimeout(Timeout.of(10, TimeUnit.SECONDS))
            .setResponseTimeout(Timeout.of(30, TimeUnit.SECONDS))
            .build();
        
        return HttpClients.custom()
            .setDefaultRequestConfig(config)
            .setUserAgent("VaultScope-Security-Scanner/1.0")
            .build();
    }

    private void testBasicConnectivity(CloseableHttpClient client, String url, 
                                     List<Vulnerability> vulnerabilities, Consumer<String> logCallback) {
        try {
            logCallback.accept("🔍 Testing basic connectivity and information disclosure...");
            HttpGet request = new HttpGet(url);
            
            try (CloseableHttpResponse response = client.execute(request)) {
                int statusCode = response.getCode();
                String responseBody = EntityUtils.toString(response.getEntity());
                
                logCallback.accept("📡 GET " + url + " → " + statusCode);
                
                if (responseBody.toLowerCase().contains("error") || 
                    responseBody.toLowerCase().contains("exception") ||
                    responseBody.toLowerCase().contains("stack trace")) {
                    
                    vulnerabilities.add(createVulnerability("MEDIUM", "Information Disclosure", url,
                        "Error information exposed in response", 
                        "Response contains error details that may reveal system information",
                        "Configure error handling to avoid exposing sensitive details to users"));
                }
                
                String serverHeader = response.getFirstHeader("Server") != null ? 
                    response.getFirstHeader("Server").getValue() : "";
                if (!serverHeader.isEmpty() && !serverHeader.contains("*")) {
                    vulnerabilities.add(createVulnerability("LOW", "Information Disclosure", url,
                        "Server information disclosed", 
                        "Server header reveals: " + serverHeader,
                        "Remove or obfuscate server header information in HTTP responses"));
                }
                
                String xPoweredBy = response.getFirstHeader("X-Powered-By") != null ?
                    response.getFirstHeader("X-Powered-By").getValue() : "";
                if (!xPoweredBy.isEmpty()) {
                    vulnerabilities.add(createVulnerability("LOW", "Information Disclosure", url,
                        "Technology stack disclosed", 
                        "X-Powered-By header reveals: " + xPoweredBy,
                        "Remove X-Powered-By header to prevent technology fingerprinting"));
                }
            }
        } catch (Exception e) {
            logCallback.accept("⚠️ Basic connectivity test failed: " + e.getMessage());
        }
    }

    private void testSqlInjection(CloseableHttpClient client, String url, 
                                List<Vulnerability> vulnerabilities, Consumer<String> logCallback) {
        logCallback.accept("🔍 Testing SQL injection vulnerabilities...");
        
        for (String payload : SQL_INJECTION_PAYLOADS) {
            try {
                String encodedPayload = URLEncoder.encode(payload, StandardCharsets.UTF_8);
                String testUrl = url + "?id=" + encodedPayload + "&user=" + encodedPayload + "&search=" + encodedPayload;
                HttpGet request = new HttpGet(testUrl);
                
                long startTime = System.currentTimeMillis();
                try (CloseableHttpResponse response = client.execute(request)) {
                    long responseTime = System.currentTimeMillis() - startTime;
                    String responseBody = EntityUtils.toString(response.getEntity());
                    
                    logCallback.accept("🧪 SQL: " + payload.substring(0, Math.min(20, payload.length())) + "... → " + response.getCode() + " (" + responseTime + "ms)");
                    
                    String lowerResponse = responseBody.toLowerCase();
                    if (lowerResponse.contains("sql syntax") || 
                        lowerResponse.contains("mysql") ||
                        lowerResponse.contains("postgresql") || 
                        lowerResponse.contains("oracle") ||
                        lowerResponse.contains("sqlite") ||
                        lowerResponse.contains("mssql") ||
                        response.getCode() == 500 || 
                        responseTime > 4000) {
                        
                        Vulnerability vuln = createVulnerability("CRITICAL", "SQL Injection", testUrl,
                            "Potential SQL injection vulnerability detected",
                            "Payload: " + payload + " | Response time: " + responseTime + "ms | Status: " + response.getCode(),
                            "Use parameterized queries, prepared statements, and input validation. Never concatenate user input directly into SQL queries.");
                        vuln.setPayload(payload);
                        vuln.setResponseCode(String.valueOf(response.getCode()));
                        vuln.setResponseTime(responseTime);
                        vulnerabilities.add(vuln);
                        
                        logCallback.accept("🚨 CRITICAL: SQL injection vulnerability detected!");
                        break;
                    }
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                logCallback.accept("⚠️ SQL injection test error: " + e.getMessage());
            }
        }
    }

    private void testNoSqlInjection(CloseableHttpClient client, String url, 
                                  List<Vulnerability> vulnerabilities, Consumer<String> logCallback) {
        logCallback.accept("🔍 Testing NoSQL injection vulnerabilities...");
        
        for (String payload : NOSQL_INJECTION_PAYLOADS) {
            try {
                HttpPost request = new HttpPost(url);
                request.setHeader("Content-Type", "application/json");
                request.setEntity(new StringEntity("{\"query\":\"" + payload + "\",\"filter\":\"" + payload + "\"}"));
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    
                    logCallback.accept("🧪 NoSQL: " + payload.substring(0, Math.min(15, payload.length())) + "... → " + response.getCode());
                    
                    String lowerResponse = responseBody.toLowerCase();
                    if (lowerResponse.contains("mongo") ||
                        lowerResponse.contains("bson") ||
                        lowerResponse.contains("nosql") ||
                        response.getCode() == 500) {
                        
                        vulnerabilities.add(createVulnerability("HIGH", "NoSQL Injection", url,
                            "Potential NoSQL injection vulnerability detected",
                            "Payload: " + payload + " caused suspicious response",
                            "Validate and sanitize all input data. Use parameterized queries for NoSQL databases."));
                        logCallback.accept("🚨 HIGH: NoSQL injection vulnerability detected!");
                    }
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                logCallback.accept("⚠️ NoSQL injection test error: " + e.getMessage());
            }
        }
    }

    private void testPathTraversal(CloseableHttpClient client, String url, 
                                 List<Vulnerability> vulnerabilities, Consumer<String> logCallback) {
        logCallback.accept("🔍 Testing path traversal vulnerabilities...");
        
        for (String payload : PATH_TRAVERSAL_PAYLOADS) {
            try {
                String testUrl = url + "/file?path=" + URLEncoder.encode(payload, StandardCharsets.UTF_8) + 
                               "&filename=" + URLEncoder.encode(payload, StandardCharsets.UTF_8);
                HttpGet request = new HttpGet(testUrl);
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    
                    logCallback.accept("🧪 Path: " + payload.substring(0, Math.min(20, payload.length())) + "... → " + response.getCode());
                    
                    if ((responseBody.contains("root:") || 
                         responseBody.contains("localhost") ||
                         responseBody.contains("admin:") ||
                         responseBody.contains("[drivers]") ||
                         responseBody.contains("daemon:")) &&
                        response.getCode() == 200) {
                        
                        vulnerabilities.add(createVulnerability("HIGH", "Path Traversal", testUrl,
                            "Directory traversal vulnerability detected",
                            "Application allows access to files outside intended directory using: " + payload,
                            "Implement proper file access controls, input validation, and use whitelist approach for file access."));
                        logCallback.accept("🚨 HIGH: Path traversal vulnerability detected!");
                        break;
                    }
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                logCallback.accept("⚠️ Path traversal test error: " + e.getMessage());
            }
        }
    }

    private void testXssVulnerabilities(CloseableHttpClient client, String url, 
                                      List<Vulnerability> vulnerabilities, Consumer<String> logCallback) {
        logCallback.accept("🔍 Testing Cross-Site Scripting (XSS) vulnerabilities...");
        
        for (String payload : XSS_PAYLOADS) {
            try {
                String encodedPayload = URLEncoder.encode(payload, StandardCharsets.UTF_8);
                String testUrl = url + "?search=" + encodedPayload + "&q=" + encodedPayload;
                HttpGet request = new HttpGet(testUrl);
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    
                    logCallback.accept("🧪 XSS: " + payload.substring(0, Math.min(15, payload.length())) + "... → " + response.getCode());
                    
                    if (responseBody.contains(payload) || 
                        responseBody.contains("<script>") ||
                        responseBody.contains("javascript:") ||
                        responseBody.contains("onerror=")) {
                        
                        vulnerabilities.add(createVulnerability("HIGH", "Cross-Site Scripting (XSS)", testUrl,
                            "Reflected XSS vulnerability detected",
                            "User input is reflected in the response without proper encoding. Payload: " + payload,
                            "Implement output encoding, Content Security Policy (CSP), and validate/sanitize all user inputs."));
                        logCallback.accept("🚨 HIGH: XSS vulnerability detected!");
                        break;
                    }
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                logCallback.accept("⚠️ XSS test error: " + e.getMessage());
            }
        }
    }

    private void testXxeVulnerabilities(CloseableHttpClient client, String url, 
                                      List<Vulnerability> vulnerabilities, Consumer<String> logCallback) {
        logCallback.accept("🔍 Testing XML External Entity (XXE) vulnerabilities...");
        
        for (String payload : XXE_PAYLOADS) {
            try {
                HttpPost request = new HttpPost(url);
                request.setHeader("Content-Type", "application/xml");
                request.setEntity(new StringEntity(payload));
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    
                    logCallback.accept("🧪 XXE test → " + response.getCode());
                    
                    if (responseBody.contains("root:") || 
                        responseBody.contains("passwd") ||
                        responseBody.contains("daemon:") ||
                        (responseBody.toLowerCase().contains("xml") && response.getCode() == 500)) {
                        
                        vulnerabilities.add(createVulnerability("CRITICAL", "XML External Entity (XXE)", url,
                            "XXE vulnerability detected",
                            "XML parser processes external entities, potentially exposing sensitive files",
                            "Disable external entity processing in XML parsers and use safe XML parsing libraries."));
                        logCallback.accept("🚨 CRITICAL: XXE vulnerability detected!");
                        break;
                    }
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                logCallback.accept("⚠️ XXE test error: " + e.getMessage());
            }
        }
    }

    private void testHttpMethodOverride(CloseableHttpClient client, String url, 
                                      List<Vulnerability> vulnerabilities, Consumer<String> logCallback) {
        logCallback.accept("🔍 Testing HTTP method security...");
        
        String[] methods = {"DELETE", "PUT", "PATCH", "TRACE", "OPTIONS", "HEAD"};
        
        for (String method : methods) {
            try {
                HttpUriRequestBase request;
                switch (method) {
                    case "DELETE" -> request = new HttpDelete(url);
                    case "PUT" -> request = new HttpPut(url);
                    case "PATCH" -> request = new HttpPatch(url);
                    case "TRACE" -> request = new HttpTrace(url);
                    case "OPTIONS" -> request = new HttpOptions(url);
                    case "HEAD" -> request = new HttpHead(url);
                    default -> continue;
                }
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    logCallback.accept("🧪 " + method + " " + url + " → " + response.getCode());
                    
                    if ((response.getCode() == 200 || response.getCode() == 204) && 
                        !method.equals("OPTIONS") && !method.equals("HEAD")) {
                        
                        vulnerabilities.add(createVulnerability("MEDIUM", "HTTP Method Override", url,
                            "Dangerous HTTP method allowed: " + method,
                            method + " method returned successful response (" + response.getCode() + ")",
                            "Restrict HTTP methods to only those required (typically GET, POST). Disable dangerous methods."));
                        logCallback.accept("⚠️ MEDIUM: " + method + " method allowed");
                    }
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                logCallback.accept("⚠️ HTTP method test error: " + e.getMessage());
            }
        }
    }

    private void testHeaderInjection(CloseableHttpClient client, String url, 
                                   List<Vulnerability> vulnerabilities, Consumer<String> logCallback) {
        logCallback.accept("🔍 Testing header injection vulnerabilities...");
        
        try {
            HttpGet request = new HttpGet(url + "?redirect=http://evil.com");
            request.setHeader("X-Forwarded-For", "127.0.0.1\r\nX-Injected: injected");
            request.setHeader("User-Agent", "VaultScope\r\nX-Injected: injected");
            
            try (CloseableHttpResponse response = client.execute(request)) {
                String responseHeaders = response.toString();
                String location = response.getFirstHeader("Location") != null ? 
                    response.getFirstHeader("Location").getValue() : "";
                
                logCallback.accept("🧪 Header Injection test → " + response.getCode());
                
                if (responseHeaders.contains("X-Injected") || location.contains("evil.com")) {
                    vulnerabilities.add(createVulnerability("MEDIUM", "Header Injection", url,
                        "Header injection vulnerability detected",
                        "Application reflects injected headers or allows open redirects",
                        "Validate and sanitize all header values and implement proper redirect validation."));
                    logCallback.accept("⚠️ MEDIUM: Header injection detected!");
                }
            }
        } catch (Exception e) {
            logCallback.accept("⚠️ Header injection test error: " + e.getMessage());
        }
    }

    private void testAuthenticationBypass(CloseableHttpClient client, String url, 
                                        List<Vulnerability> vulnerabilities, Consumer<String> logCallback) {
        logCallback.accept("🔍 Testing authentication bypass vulnerabilities...");
        
        String[][] authBypassHeaders = {
            {"X-Forwarded-User", "admin"},
            {"X-Remote-User", "administrator"},
            {"X-Forwarded-For", "127.0.0.1"},
            {"Authorization", "Bearer fake-token"},
            {"X-Original-URL", "/admin"},
            {"X-Rewrite-URL", "/admin"}
        };
        
        for (String[] header : authBypassHeaders) {
            try {
                HttpGet request = new HttpGet(url + "/admin");
                request.setHeader(header[0], header[1]);
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    logCallback.accept("🧪 Auth bypass: " + header[0] + " → " + response.getCode());
                    
                    if (response.getCode() == 200) {
                        vulnerabilities.add(createVulnerability("CRITICAL", "Authentication Bypass", url,
                            "Authentication bypass detected",
                            "Header " + header[0] + ": " + header[1] + " granted access to protected resource",
                            "Implement proper authentication and authorization checks. Do not trust client-side headers."));
                        logCallback.accept("🚨 CRITICAL: Authentication bypass detected!");
                    }
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                logCallback.accept("⚠️ Auth bypass test error: " + e.getMessage());
            }
        }
    }

    private void testRateLimiting(CloseableHttpClient client, String url, 
                                List<Vulnerability> vulnerabilities, Consumer<String> logCallback) {
        logCallback.accept("🔍 Testing rate limiting protection...");
        
        try {
            int successfulRequests = 0;
            int totalRequests = 25;
            
            for (int i = 0; i < totalRequests; i++) {
                HttpGet request = new HttpGet(url);
                
                try (CloseableHttpResponse response = client.execute(request)) {
                    if (response.getCode() == 200) {
                        successfulRequests++;
                    } else if (response.getCode() == 429) {
                        logCallback.accept("✅ Rate limiting detected at request " + (i + 1));
                        return;
                    }
                } catch (Exception e) {
                    break;
                }
                Thread.sleep(50);
            }
            
            logCallback.accept("🧪 Rate limiting: " + successfulRequests + "/" + totalRequests + " requests succeeded");
            
            if (successfulRequests >= totalRequests - 2) {
                vulnerabilities.add(createVulnerability("MEDIUM", "Missing Rate Limiting", url,
                    "No rate limiting detected",
                    "Multiple rapid requests succeeded without throttling (" + successfulRequests + "/" + totalRequests + ")",
                    "Implement rate limiting to prevent abuse, brute force attacks, and DoS attempts."));
                logCallback.accept("⚠️ MEDIUM: No rate limiting protection detected");
            }
        } catch (Exception e) {
            logCallback.accept("⚠️ Rate limiting test error: " + e.getMessage());
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