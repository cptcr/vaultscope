package dev.cptcr.vaultscope.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import dev.cptcr.vaultscope.model.SecurityResult;
import dev.cptcr.vaultscope.model.Vulnerability;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.format.DateTimeFormatter;

public class ReportService {

    private ObjectMapper objectMapper;
    private File reportsDirectory;

    public ReportService() {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
        
        this.reportsDirectory = new File("reports");
        if (!reportsDirectory.exists()) {
            reportsDirectory.mkdirs();
        }
    }

    public String exportJsonReport(SecurityResult result) throws IOException {
        String timestamp = result.getScanTimestamp().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        String filename = String.format("VaultScope_Report_%s.json", timestamp);
        File reportFile = new File(reportsDirectory, filename);
        
        objectMapper.writerWithDefaultPrettyPrinter().writeValue(reportFile, result);
        
        return reportFile.getAbsolutePath();
    }

    public String exportHtmlReport(SecurityResult result) throws IOException {
        String timestamp = result.getScanTimestamp().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        String filename = String.format("VaultScope_Report_%s.html", timestamp);
        File reportFile = new File(reportsDirectory, filename);
        
        String htmlContent = generateHtmlReport(result);
        
        try (FileWriter writer = new FileWriter(reportFile)) {
            writer.write(htmlContent);
        }
        
        return reportFile.getAbsolutePath();
    }

    private String generateHtmlReport(SecurityResult result) {
        StringBuilder html = new StringBuilder();
        
        html.append("<!DOCTYPE html>\n");
        html.append("<html lang=\"en\">\n");
        html.append("<head>\n");
        html.append("    <meta charset=\"UTF-8\">\n");
        html.append("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.append("    <title>VaultScope Security Assessment Report</title>\n");
        html.append("    <style>\n");
        html.append(getReportCSS());
        html.append("    </style>\n");
        html.append("</head>\n");
        html.append("<body>\n");
        
        html.append("    <div class=\"container\">\n");
        html.append("        <header class=\"report-header\">\n");
        html.append("            <div class=\"header-content\">\n");
        html.append("                <h1>🛡️ VaultScope Security Assessment Report</h1>\n");
        html.append("                <div class=\"header-meta\">\n");
        html.append("                    <div class=\"meta-item\">\n");
        html.append("                        <strong>Target:</strong> ").append(escapeHtml(result.getTargetUrl())).append("\n");
        html.append("                    </div>\n");
        html.append("                    <div class=\"meta-item\">\n");
        html.append("                        <strong>Scan Date:</strong> ").append(result.getScanTimestamp().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))).append("\n");
        html.append("                    </div>\n");
        html.append("                    <div class=\"meta-item\">\n");
        html.append("                        <strong>Duration:</strong> ").append(result.getScanDuration() != null ? result.getScanDuration() : "N/A").append("\n");
        html.append("                    </div>\n");
        html.append("                    <div class=\"score-display\">\n");
        html.append("                        <strong>Security Score:</strong> <span class=\"score-value\">").append(result.getSecurityScore()).append("/100</span>\n");
        html.append("                        <span class=\"score-grade\">").append(getScoreGrade(result.getSecurityScore())).append("</span>\n");
        html.append("                    </div>\n");
        html.append("                </div>\n");
        html.append("            </div>\n");
        html.append("        </header>\n");
        
        html.append("        <section class=\"executive-summary\">\n");
        html.append("            <h2>📊 Executive Summary</h2>\n");
        html.append("            <div class=\"summary-grid\">\n");
        html.append("                <div class=\"summary-card total\">\n");
        html.append("                    <div class=\"card-header\">Total Issues</div>\n");
        html.append("                    <div class=\"card-value\">").append(result.getVulnerabilities().size()).append("</div>\n");
        html.append("                </div>\n");
                        html.append("                <div class=\"summary-card critical\">\n");
        html.append("                    <div class=\"card-header\">Critical</div>\n");
        html.append("                    <div class=\"card-value\">").append(countVulnerabilitiesBySeverity(result, "CRITICAL")).append("</div>\n");
        html.append("                </div>\n");
        html.append("                <div class=\"summary-card high\">\n");
        html.append("                    <div class=\"card-header\">High</div>\n");
        html.append("                    <div class=\"card-value\">").append(countVulnerabilitiesBySeverity(result, "HIGH")).append("</div>\n");
        html.append("                </div>\n");
        html.append("                <div class=\"summary-card medium\">\n");
        html.append("                    <div class=\"card-header\">Medium</div>\n");
        html.append("                    <div class=\"card-value\">").append(countVulnerabilitiesBySeverity(result, "MEDIUM")).append("</div>\n");
        html.append("                </div>\n");
        html.append("                <div class=\"summary-card low\">\n");
        html.append("                    <div class=\"card-header\">Low</div>\n");
        html.append("                    <div class=\"card-value\">").append(countVulnerabilitiesBySeverity(result, "LOW")).append("</div>\n");
        html.append("                </div>\n");
        html.append("            </div>\n");
        html.append("        </section>\n");
        
        if (result.getVulnerabilities().isEmpty()) {
            html.append("        <section class=\"no-vulnerabilities\">\n");
            html.append("            <div class=\"success-message\">\n");
            html.append("                <h2>🎉 Excellent Security Posture!</h2>\n");
            html.append("                <p>No security vulnerabilities were detected during this comprehensive assessment.</p>\n");
            html.append("                <p>Your API demonstrates good security practices and appears to be well-protected against common attack vectors.</p>\n");
            html.append("            </div>\n");
            html.append("        </section>\n");
        } else {
            html.append("        <section class=\"vulnerabilities-section\">\n");
            html.append("            <h2>🔍 Vulnerability Details</h2>\n");
            
            for (Vulnerability vuln : result.getVulnerabilities()) {
                html.append("            <div class=\"vulnerability-card ").append(vuln.getSeverity().toLowerCase()).append("\">\n");
                html.append("                <div class=\"vuln-header\">\n");
                html.append("                    <h3 class=\"vuln-title\">").append(escapeHtml(vuln.getType())).append("</h3>\n");
                html.append("                    <span class=\"severity-badge ").append(vuln.getSeverity().toLowerCase()).append("\">").append(vuln.getSeverity()).append("</span>\n");
                html.append("                </div>\n");
                html.append("                <div class=\"vuln-content\">\n");
                html.append("                    <div class=\"vuln-field\">\n");
                html.append("                        <strong>Endpoint:</strong> <code>").append(escapeHtml(vuln.getEndpoint())).append("</code>\n");
                html.append("                    </div>\n");
                html.append("                    <div class=\"vuln-field\">\n");
                html.append("                        <strong>Description:</strong> ").append(escapeHtml(vuln.getDescription())).append("\n");
                html.append("                    </div>\n");
                html.append("                    <div class=\"vuln-field\">\n");
                html.append("                        <strong>Technical Details:</strong> ").append(escapeHtml(vuln.getDetails())).append("\n");
                html.append("                    </div>\n");
                if (vuln.getPayload() != null && !vuln.getPayload().isEmpty()) {
                    html.append("                    <div class=\"vuln-field\">\n");
                    html.append("                        <strong>Payload:</strong> <code>").append(escapeHtml(vuln.getPayload())).append("</code>\n");
                    html.append("                    </div>\n");
                }
                html.append("                    <div class=\"vuln-recommendation\">\n");
                html.append("                        <strong>💡 Recommendation:</strong> ").append(escapeHtml(vuln.getRecommendation())).append("\n");
                html.append("                    </div>\n");
                html.append("                </div>\n");
                html.append("            </div>\n");
            }
            
            html.append("        </section>\n");
        }
        
        html.append("        <footer class=\"report-footer\">\n");
        html.append("            <div class=\"footer-content\">\n");
        html.append("                <p><strong>Generated by VaultScope</strong> - Enterprise API Security Assessment Tool</p>\n");
        html.append("                <div class=\"footer-links\">\n");
        html.append("                    <span>Author: <strong>CPTCR</strong></span> | \n");
        html.append("                    <a href=\"https://cptcr.dev\" target=\"_blank\">cptcr.dev</a> | \n");
        html.append("                    <a href=\"https://github.com/cptcr\" target=\"_blank\">GitHub</a>\n");
        html.append("                </div>\n");
        html.append("                <p class=\"disclaimer\">This report contains security assessment results for localhost testing only. Use responsibly and only on systems you own or have explicit permission to test.</p>\n");
        html.append("            </div>\n");
        html.append("        </footer>\n");
        html.append("    </div>\n");
        html.append("</body>\n");
        html.append("</html>");
        
        return html.toString();
    }

    private String getReportCSS() {
        return """
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                line-height: 1.6;
                color: #2c3e50;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }
            
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                border-radius: 12px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.1);
                overflow: hidden;
            }
            
            .report-header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 40px;
                text-align: center;
            }
            
            .header-content h1 {
                font-size: 2.5em;
                margin-bottom: 20px;
                font-weight: 700;
            }
            
            .header-meta {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-top: 30px;
            }
            
            .meta-item {
                background: rgba(255,255,255,0.1);
                padding: 15px;
                border-radius: 8px;
                backdrop-filter: blur(10px);
            }
            
            .score-display {
                grid-column: 1 / -1;
                text-align: center;
                font-size: 1.2em;
            }
            
            .score-value {
                font-size: 2em;
                font-weight: bold;
                color: #ffd700;
            }
            
            .score-grade {
                font-size: 1.5em;
                font-weight: bold;
                margin-left: 10px;
                padding: 5px 15px;
                background: rgba(255,255,255,0.2);
                border-radius: 20px;
            }
            
            .executive-summary {
                padding: 40px;
                background: #f8f9fa;
            }
            
            .executive-summary h2 {
                color: #2c3e50;
                margin-bottom: 30px;
                font-size: 1.8em;
                text-align: center;
            }
            
            .summary-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
            }
            
            .summary-card {
                background: white;
                padding: 25px;
                border-radius: 10px;
                text-align: center;
                box-shadow: 0 4px 15px rgba(0,0,0,0.08);
                border-left: 5px solid;
            }
            
            .summary-card.total { border-left-color: #3498db; }
            .summary-card.critical { border-left-color: #e74c3c; }
            .summary-card.high { border-left-color: #f39c12; }
            .summary-card.medium { border-left-color: #f1c40f; }
            .summary-card.low { border-left-color: #27ae60; }
            
            .card-header {
                font-size: 0.9em;
                color: #7f8c8d;
                text-transform: uppercase;
                font-weight: 600;
                margin-bottom: 10px;
            }
            
            .card-value {
                font-size: 2.5em;
                font-weight: bold;
                color: #2c3e50;
            }
            
            .vulnerabilities-section {
                padding: 40px;
            }
            
            .vulnerabilities-section h2 {
                color: #2c3e50;
                margin-bottom: 30px;
                font-size: 1.8em;
                text-align: center;
            }
            
            .vulnerability-card {
                background: white;
                border-radius: 10px;
                margin-bottom: 25px;
                box-shadow: 0 4px 15px rgba(0,0,0,0.08);
                border-left: 5px solid;
                overflow: hidden;
            }
            
            .vulnerability-card.critical { border-left-color: #e74c3c; }
            .vulnerability-card.high { border-left-color: #f39c12; }
            .vulnerability-card.medium { border-left-color: #f1c40f; }
            .vulnerability-card.low { border-left-color: #27ae60; }
            
            .vuln-header {
                background: #f8f9fa;
                padding: 20px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                border-bottom: 1px solid #dee2e6;
            }
            
            .vuln-title {
                margin: 0;
                color: #2c3e50;
                font-size: 1.3em;
            }
            
            .severity-badge {
                padding: 8px 16px;
                border-radius: 25px;
                font-size: 0.85em;
                font-weight: bold;
                text-transform: uppercase;
                color: white;
            }
            
            .severity-badge.critical { background: #e74c3c; }
            .severity-badge.high { background: #f39c12; }
            .severity-badge.medium { background: #f1c40f; color: #333; }
            .severity-badge.low { background: #27ae60; }
            
            .vuln-content {
                padding: 25px;
            }
            
            .vuln-field {
                margin-bottom: 15px;
            }
            
            .vuln-field strong {
                color: #2c3e50;
                display: inline-block;
                min-width: 120px;
            }
            
            .vuln-recommendation {
                background: #e8f5e8;
                padding: 15px;
                border-radius: 6px;
                border-left: 4px solid #27ae60;
                margin-top: 20px;
            }
            
            code {
                background: #f8f9fa;
                padding: 2px 6px;
                border-radius: 4px;
                font-family: 'Courier New', monospace;
                color: #e74c3c;
            }
            
            .no-vulnerabilities {
                padding: 60px 40px;
                text-align: center;
            }
            
            .success-message {
                background: linear-gradient(135deg, #56ab2f 0%, #a8e6cf 100%);
                color: white;
                padding: 40px;
                border-radius: 15px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            }
            
            .success-message h2 {
                font-size: 2.2em;
                margin-bottom: 20px;
            }
            
            .success-message p {
                font-size: 1.1em;
                margin-bottom: 15px;
            }
            
            .report-footer {
                background: #2c3e50;
                color: white;
                padding: 30px 40px;
                text-align: center;
            }
            
            .footer-content p {
                margin-bottom: 10px;
            }
            
            .footer-links {
                margin: 15px 0;
            }
            
            .footer-links a {
                color: #3498db;
                text-decoration: none;
            }
            
            .footer-links a:hover {
                text-decoration: underline;
            }
            
            .disclaimer {
                font-size: 0.9em;
                color: #bdc3c7;
                font-style: italic;
                margin-top: 20px;
            }
            
            @media (max-width: 768px) {
                .container {
                    margin: 10px;
                    border-radius: 8px;
                }
                
                .report-header, .executive-summary, .vulnerabilities-section {
                    padding: 20px;
                }
                
                .header-meta {
                    grid-template-columns: 1fr;
                }
                
                .vuln-header {
                    flex-direction: column;
                    align-items: flex-start;
                    gap: 10px;
                }
            }
            """;
    }

    private String getScoreGrade(int score) {
        if (score >= 90) return "A";
        if (score >= 80) return "B";
        if (score >= 70) return "C";
        if (score >= 60) return "D";
        return "F";
    }

    private long countVulnerabilitiesBySeverity(SecurityResult result, String severity) {
        return result.getVulnerabilities().stream()
            .filter(v -> severity.equals(v.getSeverity()))
            .count();
    }

    private String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                  .replace("<", "&lt;")
                  .replace(">", "&gt;")
                  .replace("\"", "&quot;")
                  .replace("'", "&#x27;");
    }