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
        String filename = String.format("vaultscope_report_%s.json", timestamp);
        File reportFile = new File(reportsDirectory, filename);
        
        objectMapper.writerWithDefaultPrettyPrinter().writeValue(reportFile, result);
        
        return reportFile.getAbsolutePath();
    }

    public String exportHtmlReport(SecurityResult result) throws IOException {
        String timestamp = result.getScanTimestamp().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        String filename = String.format("vaultscope_report_%s.html", timestamp);
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
        html.append("    <title>VaultScope Security Report</title>\n");
        html.append("    <style>\n");
        html.append(getReportCSS());
        html.append("    </style>\n");
        html.append("</head>\n");
        html.append("<body>\n");
        
        html.append("    <div class=\"container\">\n");
        html.append("        <header>\n");
        html.append("            <h1>VaultScope Security Assessment Report</h1>\n");
        html.append("            <div class=\"meta-info\">\n");
        html.append("                <p><strong>Target:</strong> ").append(result.getTargetUrl()).append("</p>\n");
        html.append("                <p><strong>Scan Date:</strong> ").append(result.getScanTimestamp().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))).append("</p>\n");
        html.append("                <p><strong>Security Score:</strong> <span class=\"score\">").append(result.getSecurityScore()).append("/100</span></p>\n");
        html.append("            </div>\n");
        html.append("        </header>\n");
        
        html.append("        <section class=\"summary\">\n");
        html.append("            <h2>Executive Summary</h2>\n");
        html.append("            <div class=\"summary-stats\">\n");
        html.append("                <div class=\"stat-card critical\">\n");
        html.append("                    <h3>").append(countVulnerabilitiesBySeverity(result, "CRITICAL")).append("</h3>\n");
        html.append("                    <p>Critical</p>\n");
        html.append("                </div>\n");
        html.append("                <div class=\"stat-card high\">\n");
        html.append("                    <h3>").append(countVulnerabilitiesBySeverity(result, "HIGH")).append("</h3>\n");
        html.append("                    <p>High</p>\n");
        html.append("                </div>\n");
        html.append("                <div class=\"stat-card medium\">\n");
        html.append("                    <h3>").append(countVulnerabilitiesBySeverity(result, "MEDIUM")).append("</h3>\n");
        html.append("                    <p>Medium</p>\n");
        html.append("                </div>\n");
        html.append("                <div class=\"stat-card low\">\n");
        html.append("                    <h3>").append(countVulnerabilitiesBySeverity(result, "LOW")).append("</h3>\n");
        html.append("                    <p>Low</p>\n");
        html.append("                </div>\n");
        html.append("            </div>\n");
        html.append("        </section>\n");
        
        html.append("        <section class=\"vulnerabilities\">\n");
        html.append("            <h2>Vulnerability Details</h2>\n");
        
        if (result.getVulnerabilities().isEmpty()) {
            html.append("            <p class=\"no-vulnerabilities\">No vulnerabilities detected during the scan.</p>\n");
        } else {
            for (Vulnerability vuln : result.getVulnerabilities()) {
                html.append("            <div class=\"vulnerability ").append(vuln.getSeverity().toLowerCase()).append("\">\n");
                html.append("                <div class=\"vuln-header\">\n");
                html.append("                    <h3>").append(escapeHtml(vuln.getType())).append("</h3>\n");
                html.append("                    <span class=\"severity-badge ").append(vuln.getSeverity().toLowerCase()).append("\">").append(vuln.getSeverity()).append("</span>\n");
                html.append("                </div>\n");
                html.append("                <p><strong>Endpoint:</strong> ").append(escapeHtml(vuln.getEndpoint())).append("</p>\n");
                html.append("                <p><strong>Description:</strong> ").append(escapeHtml(vuln.getDescription())).append("</p>\n");
                html.append("                <p><strong>Details:</strong> ").append(escapeHtml(vuln.getDetails())).append("</p>\n");
                html.append("                <p><strong>Recommendation:</strong> ").append(escapeHtml(vuln.getRecommendation())).append("</p>\n");
                html.append("            </div>\n");
            }
        }
        
        html.append("        </section>\n");
        
        html.append("        <footer>\n");
        html.append("            <p>Generated by VaultScope - Enterprise API Security Assessment Tool</p>\n");
        html.append("            <p>Author: CPTCR | <a href=\"https://cptcr.dev\">cptcr.dev</a> | <a href=\"https://github.com/cptcr\">GitHub</a></p>\n");
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
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                line-height: 1.6;
                color: #333;
                background-color: #f5f5f5;
            }
            
            .container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
                background: white;
                box-shadow: 0 0 20px rgba(0,0,0,0.1);
            }
            
            header {
                border-bottom: 3px solid #007acc;
                padding-bottom: 20px;
                margin-bottom: 30px;
            }
            
            h1 {
                color: #007acc;
                font-size: 2.5em;
                margin-bottom: 15px;
            }
            
            h2 {
                color: #333;
                font-size: 1.8em;
                margin-bottom: 20px;
                border-bottom: 2px solid #eee;
                padding-bottom: 10px;
            }
            
            .meta-info p {
                margin-bottom: 8px;
                font-size: 1.1em;
            }
            
            .score {
                font-weight: bold;
                color: #007acc;
                font-size: 1.2em;
            }
            
            .summary-stats {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            
            .stat-card {
                padding: 20px;
                border-radius: 8px;
                text-align: center;
                color: white;
                font-weight: bold;
            }
            
            .stat-card.critical { background-color: #dc3545; }
            .stat-card.high { background-color: #fd7e14; }
            .stat-card.medium { background-color: #ffc107; color: #333; }
            .stat-card.low { background-color: #28a745; }
            
            .stat-card h3 {
                font-size: 2.5em;
                margin-bottom: 5px;
            }
            
            .vulnerability {
                border: 1px solid #ddd;
                border-radius: 8px;
                padding: 20px;
                margin-bottom: 20px;
                border-left: 5px solid;
            }
            
            .vulnerability.critical { border-left-color: #dc3545; }
            .vulnerability.high { border-left-color: #fd7e14; }
            .vulnerability.medium { border-left-color: #ffc107; }
            .vulnerability.low { border-left-color: #28a745; }
            
            .vuln-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 15px;
            }
            
            .vuln-header h3 {
                margin: 0;
                color: #333;
            }
            
            .severity-badge {
                padding: 5px 12px;
                border-radius: 20px;
                font-size: 0.8em;
                font-weight: bold;
                text-transform: uppercase;
                color: white;
            }
            
            .severity-badge.critical { background-color: #dc3545; }
            .severity-badge.high { background-color: #fd7e14; }
            .severity-badge.medium { background-color: #ffc107; color: #333; }
            .severity-badge.low { background-color: #28a745; }
            
            .vulnerability p {
                margin-bottom: 10px;
            }
            
            .no-vulnerabilities {
                text-align: center;
                color: #28a745;
                font-size: 1.2em;
                font-weight: bold;
                padding: 40px;
                background-color: #d4edda;
                border-radius: 8px;
            }
            
            footer {
                margin-top: 40px;
                padding-top: 20px;
                border-top: 2px solid #eee;
                text-align: center;
                color: #666;
            }
            
            footer a {
                color: #007acc;
                text-decoration: none;
            }
            
            footer a:hover {
                text-decoration: underline;
            }
            """;
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
}