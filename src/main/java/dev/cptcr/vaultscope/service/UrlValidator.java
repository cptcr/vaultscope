package dev.cptcr.vaultscope.service;

import java.net.URI;
import java.util.regex.Pattern;

public class UrlValidator {
    
    private static final Pattern LOCALHOST_PATTERN = Pattern.compile(
        "^(https?://)?(localhost|127\\.0\\.0\\.1)(:\\d+)?(/.*)?$",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern IP_PATTERN = Pattern.compile(
        "^127\\.0\\.0\\.1$"
    );

    public boolean isValidLocalhostUrl(String url) {
        if (url == null || url.trim().isEmpty()) {
            return false;
        }

        String normalizedUrl = url.trim();
        if (!normalizedUrl.startsWith("http://") && !normalizedUrl.startsWith("https://")) {
            normalizedUrl = "http://" + normalizedUrl;
        }

        try {
            URI uri = new URI(normalizedUrl);
            String host = uri.getHost();
            
            if (host == null) {
                return false;
            }

            return "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host);
        } catch (Exception e) {
            return LOCALHOST_PATTERN.matcher(url.trim()).matches();
        }
    }

    public String normalizeUrl(String url) {
        if (url == null || url.trim().isEmpty()) {
            return null;
        }

        String normalized = url.trim();
        if (!normalized.startsWith("http://") && !normalized.startsWith("https://")) {
            normalized = "http://" + normalized;
        }

        try {
            URI uri = new URI(normalized);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            int port = uri.getPort();
            String path = uri.getPath();
            
            if (host == null) {
                return null;
            }
            
            StringBuilder result = new StringBuilder();
            result.append(scheme != null ? scheme : "http").append("://");
            result.append(host);
            
            if (port != -1) {
                result.append(":").append(port);
            }
            
            if (path != null && !path.isEmpty() && !"/".equals(path)) {
                result.append(path);
            }
            
            return result.toString();
        } catch (Exception e) {
            return null;
        }
    }

    public boolean isSecureConnection(String url) {
        return url != null && url.toLowerCase().startsWith("https://");
    }

    public String extractHost(String url) {
        try {
            String normalized = normalizeUrl(url);
            if (normalized != null) {
                URI uri = new URI(normalized);
                return uri.getHost();
            }
        } catch (Exception e) {
        }
        return null;
    }

    public int extractPort(String url) {
        try {
            String normalized = normalizeUrl(url);
            if (normalized != null) {
                URI uri = new URI(normalized);
                return uri.getPort();
            }
        } catch (Exception e) {
        }
        return -1;
    }
}