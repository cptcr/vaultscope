package dev.cptcr.vaultscope.service;

import java.net.URI;
import java.util.regex.Pattern;

public class UrlValidator {
    
    private static final Pattern LOCALHOST_PATTERN = Pattern.compile(
        "^(https?://)?(localhost|127\\.0\\.0\\.1)(:\\d+)?(/.*)?$",
        Pattern.CASE_INSENSITIVE
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
            return false;
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
            return uri.toString();
        } catch (Exception e) {
            return null;
        }
    }
}