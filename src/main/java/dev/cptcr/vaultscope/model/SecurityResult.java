package dev.cptcr.vaultscope.model;

import java.time.LocalDateTime;
import java.util.List;

public class SecurityResult {
    private String targetUrl;
    private LocalDateTime scanTimestamp;
    
    private List<Vulnerability> vulnerabilities;
    private int securityScore;
    private String scanDuration;

    public SecurityResult() {}

    public SecurityResult(String targetUrl, List<Vulnerability> vulnerabilities, long scanDurationMs) {
        this.targetUrl = targetUrl;
        this.scanTimestamp = LocalDateTime.now();
        this.vulnerabilities = vulnerabilities;
        this.securityScore = calculateScore(vulnerabilities);
        this.scanDuration = formatDuration(scanDurationMs);
    }
    
    public SecurityResult(String targetUrl, LocalDateTime scanTimestamp, 
                         List<Vulnerability> vulnerabilities, int securityScore) {
        this.targetUrl = targetUrl;
        this.scanTimestamp = scanTimestamp;
        this.vulnerabilities = vulnerabilities;
        this.securityScore = securityScore;
    }

    public String getTargetUrl() {
        return targetUrl;
    }

    public void setTargetUrl(String targetUrl) {
        this.targetUrl = targetUrl;
    }

    public LocalDateTime getScanTimestamp() {
        return scanTimestamp;
    }

    public void setScanTimestamp(LocalDateTime scanTimestamp) {
        this.scanTimestamp = scanTimestamp;
    }

    public List<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(List<Vulnerability> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public int getSecurityScore() {
        return securityScore;
    }

    public void setSecurityScore(int securityScore) {
        this.securityScore = securityScore;
    }

    public String getScanDuration() {
        return scanDuration;
    }

    public void setScanDuration(String scanDuration) {
        this.scanDuration = scanDuration;
    }
    
    private int calculateScore(List<Vulnerability> vulnerabilities) {
        if (vulnerabilities == null || vulnerabilities.isEmpty()) {
            return 100;
        }
        
        int deductions = 0;
        for (Vulnerability vuln : vulnerabilities) {
            switch (vuln.getSeverity().toLowerCase()) {
                case "critical" -> deductions += 30;
                case "high" -> deductions += 20;
                case "medium" -> deductions += 10;
                case "low" -> deductions += 5;
            }
        }
        
        return Math.max(0, 100 - deductions);
    }
    
    private String formatDuration(long durationMs) {
        if (durationMs < 1000) {
            return durationMs + "ms";
        } else if (durationMs < 60000) {
            return String.format("%.1fs", durationMs / 1000.0);
        } else {
            long minutes = durationMs / 60000;
            long seconds = (durationMs % 60000) / 1000;
            return String.format("%dm %ds", minutes, seconds);
        }
    }
}