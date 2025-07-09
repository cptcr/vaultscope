package dev.cptcr.vaultscope.model;

import com.fasterxml.jackson.annotation.JsonFormat;

import java.time.LocalDateTime;
import java.util.List;

public class SecurityResult {
    private String targetUrl;
    
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime scanTimestamp;
    
    private List<Vulnerability> vulnerabilities;
    private int securityScore;
    private String scanDuration;

    public SecurityResult() {}

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
}