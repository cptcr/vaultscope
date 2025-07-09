import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class VaultScope extends JFrame {
    private JTextField urlField;
    private JButton scanButton, exportButton, themeButton;
    private JTextArea logArea, detailsArea;
    private JTable vulnTable;
    private DefaultTableModel tableModel;
    private JLabel scoreLabel, statusLabel;
    private List<Vulnerability> currentResults = new ArrayList<>();
    private boolean isDarkTheme = false;
    
    public VaultScope() {
        setTitle("VaultScope - Enterprise API Security Assessment");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1400, 900);
        setLocationRelativeTo(null);
        initUI();
        applyTheme();
    }
    
    private void initUI() {
        setLayout(new BorderLayout());
        
        JPanel leftPanel = new JPanel();
        leftPanel.setLayout(new BoxLayout(leftPanel, BoxLayout.Y_AXIS));
        leftPanel.setPreferredSize(new Dimension(300, 0));
        leftPanel.setBorder(BorderFactory.createTitledBorder("Control Panel"));
        
        leftPanel.add(Box.createVerticalStrut(10));
        leftPanel.add(new JLabel("Target URL:"));
        urlField = new JTextField("localhost:8080");
        urlField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 25));
        leftPanel.add(urlField);
        
        leftPanel.add(Box.createVerticalStrut(10));
        scanButton = new JButton("🔍 Start Security Scan");
        scanButton.setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));
        scanButton.addActionListener(this::performScan);
        leftPanel.add(scanButton);
        
        leftPanel.add(Box.createVerticalStrut(20));
        scoreLabel = new JLabel("Security Score: --");
        scoreLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 16));
        leftPanel.add(scoreLabel);
        
        leftPanel.add(Box.createVerticalStrut(20));
        exportButton = new JButton("📄 Export Report");
        exportButton.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        exportButton.addActionListener(this::exportReport);
        exportButton.setEnabled(false);
        leftPanel.add(exportButton);
        
        leftPanel.add(Box.createVerticalStrut(10));
        themeButton = new JButton("🌙 Dark Theme");
        themeButton.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        themeButton.addActionListener(this::toggleTheme);
        leftPanel.add(themeButton);
        
        leftPanel.add(Box.createVerticalGlue());
        
        add(leftPanel, BorderLayout.WEST);
        
        JTabbedPane tabbedPane = new JTabbedPane();
        
        JPanel vulnPanel = new JPanel(new BorderLayout());
        String[] columns = {"Severity", "Type", "Endpoint", "Description"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };
        vulnTable = new JTable(tableModel);
        vulnTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        vulnTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = vulnTable.getSelectedRow();
                if (row >= 0 && row < currentResults.size()) {
                    showVulnerabilityDetails(currentResults.get(row));
                }
            }
        });
        
        JSplitPane vulnSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        vulnSplit.setTopComponent(new JScrollPane(vulnTable));
        
        detailsArea = new JTextArea();
        detailsArea.setEditable(false);
        detailsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        detailsArea.setText("Select a vulnerability above to see details...");
        vulnSplit.setBottomComponent(new JScrollPane(detailsArea));
        vulnSplit.setDividerLocation(300);
        
        vulnPanel.add(vulnSplit);
        tabbedPane.addTab("🛡️ Vulnerabilities", vulnPanel);
        
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        tabbedPane.addTab("📊 Traffic Log", new JScrollPane(logArea));
        
        add(tabbedPane, BorderLayout.CENTER);
        
        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statusLabel = new JLabel("Ready to scan localhost APIs");
        statusPanel.add(statusLabel);
        add(statusPanel, BorderLayout.SOUTH);
    }
    
    private void performScan(ActionEvent e) {
        String targetUrl = urlField.getText().trim();
        
        if (!isValidLocalhostUrl(targetUrl)) {
            JOptionPane.showMessageDialog(this, 
                "❌ Invalid URL!\n\nOnly localhost URLs are allowed for security.\n\nExamples:\n• localhost:8080\n• 127.0.0.1:3000\n• http://localhost/api", 
                "Invalid Target", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        scanButton.setEnabled(false);
        exportButton.setEnabled(false);
        tableModel.setRowCount(0);
        currentResults.clear();
        logArea.setText("");
        detailsArea.setText("Scan in progress...");
        scoreLabel.setText("Security Score: Scanning...");
        statusLabel.setText("🔄 Security scan in progress...");
        
        new Thread(() -> {
            try {
                List<Vulnerability> vulnerabilities = performSecurityTests(targetUrl);
                
                SwingUtilities.invokeLater(() -> {
                    currentResults = vulnerabilities;
                    for (Vulnerability vuln : vulnerabilities) {
                        String[] row = {vuln.severity, vuln.type, vuln.endpoint, vuln.description};
                        tableModel.addRow(row);
                    }
                    
                    int score = calculateSecurityScore(vulnerabilities);
                    String grade = getSecurityGrade(score);
                    scoreLabel.setText(String.format("Security Score: %d/100 (%s)", score, grade));
                    
                    Color scoreColor = score >= 80 ? new Color(34, 139, 34) : 
                                     score >= 60 ? new Color(255, 140, 0) : Color.RED;
                    scoreLabel.setForeground(scoreColor);
                    
                    statusLabel.setText(String.format("✅ Scan complete - Found %d issues", vulnerabilities.size()));
                    exportButton.setEnabled(true);
                    scanButton.setEnabled(true);
                    detailsArea.setText("Scan completed!\n\nSelect a vulnerability from the table above to view details.");
                    
                    if (vulnerabilities.isEmpty()) {
                        detailsArea.setText("🎉 EXCELLENT!\n\nNo security vulnerabilities detected!\nYour API appears to be well-secured.");
                    }
                });
                
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("❌ Scan failed");
                    scoreLabel.setText("Security Score: Error");
                    scoreLabel.setForeground(Color.RED);
                    scanButton.setEnabled(true);
                    detailsArea.setText("❌ Scan Error:\n\n" + ex.getMessage() + 
                        "\n\nPlease ensure the target server is running and accessible.");
                    logArea.append("\n❌ ERROR: " + ex.getMessage());
                });
            }
        }).start();
    }
    
    private boolean isValidLocalhostUrl(String url) {
        if (url == null || url.trim().isEmpty()) return false;
        String normalized = url.toLowerCase().trim();
        return normalized.matches("^(https?://)?(localhost|127\\.0\\.0\\.1)(:\\d+)?(/.*)?$");
    }
    
    private List<Vulnerability> performSecurityTests(String targetUrl) throws Exception {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (!targetUrl.startsWith("http")) {
            targetUrl = "http://" + targetUrl;
        }
        
        log("🚀 Starting comprehensive security scan...");
        log("🎯 Target: " + targetUrl);
        log("⏰ Time: " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
        log("" + "=".repeat(60));
        
        testBasicConnectivity(targetUrl, vulnerabilities);
        testSqlInjection(targetUrl, vulnerabilities);
        testXssVulnerabilities(targetUrl, vulnerabilities);
        testPathTraversal(targetUrl, vulnerabilities);
        testHttpMethods(targetUrl, vulnerabilities);
        testRateLimiting(targetUrl, vulnerabilities);
        
        log("" + "=".repeat(60));
        log(String.format("✅ Scan completed! Found %d potential security issues.", vulnerabilities.size()));
        
        return vulnerabilities;
    }
    
    private void testBasicConnectivity(String baseUrl, List<Vulnerability> vulnerabilities) throws Exception {
        log("🔍 Testing basic connectivity...");
        
        HttpURLConnection conn = createConnection(baseUrl);
        int responseCode = conn.getResponseCode();
        String serverHeader = conn.getHeaderField("Server");
        
        log("📡 Response Code: " + responseCode);
        
        if (serverHeader != null && !serverHeader.isEmpty()) {
            vulnerabilities.add(new Vulnerability("LOW", "Information Disclosure", 
                baseUrl, "Server header reveals software details: " + serverHeader,
                "The server exposes version information that could help attackers.",
                "Configure server to hide or obfuscate version information."));
            log("⚠️  Found: Server header disclosure - " + serverHeader);
        }
        
        String responseBody = readResponse(conn);
        if (responseBody.toLowerCase().contains("error") || responseBody.toLowerCase().contains("exception")) {
            vulnerabilities.add(new Vulnerability("MEDIUM", "Information Disclosure", 
                baseUrl, "Error details exposed in response",
                "Application reveals internal error information to users.",
                "Implement proper error handling to avoid exposing sensitive details."));
            log("⚠️  Found: Error information disclosure");
        }
        
        Thread.sleep(200);
    }
    
    private void testSqlInjection(String baseUrl, List<Vulnerability> vulnerabilities) throws Exception {
        log("🔍 Testing SQL injection vulnerabilities...");
        
        String[] payloads = {"' OR '1'='1", "'; DROP TABLE users--", "' UNION SELECT NULL--", "1' AND SLEEP(5)--"};
        
        for (String payload : payloads) {
            try {
                String testUrl = baseUrl + "?id=" + payload + "&user=" + payload;
                HttpURLConnection conn = createConnection(testUrl);
                
                long startTime = System.currentTimeMillis();
                int responseCode = conn.getResponseCode();
                long responseTime = System.currentTimeMillis() - startTime;
                String responseBody = readResponse(conn);
                
                log("🧪 SQL Test: " + payload + " → " + responseCode + " (" + responseTime + "ms)");
                
                String lowerResponse = responseBody.toLowerCase();
                if (lowerResponse.contains("sql") || lowerResponse.contains("mysql") || 
                    lowerResponse.contains("postgresql") || lowerResponse.contains("oracle") ||
                    responseCode == 500 || responseTime > 4000) {
                    
                    vulnerabilities.add(new Vulnerability("CRITICAL", "SQL Injection", 
                        testUrl, "Potential SQL injection vulnerability detected",
                        "Payload '" + payload + "' caused suspicious database response. " +
                        "Response time: " + responseTime + "ms, Status: " + responseCode,
                        "Use parameterized queries and input validation. Never concatenate user input directly into SQL queries."));
                    log("🚨 CRITICAL: SQL injection vulnerability detected!");
                    break;
                }
                
                Thread.sleep(150);
            } catch (Exception e) {
                log("⚠️  SQL test error: " + e.getMessage());
            }
        }
    }
    
    private void testXssVulnerabilities(String baseUrl, List<Vulnerability> vulnerabilities) throws Exception {
        log("🔍 Testing Cross-Site Scripting (XSS) vulnerabilities...");
        
        String[] payloads = {
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "'\"><script>alert('XSS')</script>"
        };
        
        for (String payload : payloads) {
            try {
                String testUrl = baseUrl + "?search=" + payload + "&q=" + payload;
                HttpURLConnection conn = createConnection(testUrl);
                String responseBody = readResponse(conn);
                
                log("🧪 XSS Test: " + payload.substring(0, Math.min(20, payload.length())) + "... → " + conn.getResponseCode());
                
                if (responseBody.contains(payload) || responseBody.contains("<script>") || 
                    responseBody.contains("javascript:")) {
                    
                    vulnerabilities.add(new Vulnerability("HIGH", "Cross-Site Scripting (XSS)", 
                        testUrl, "Reflected XSS vulnerability detected",
                        "User input is reflected in the response without proper encoding. Payload: " + payload,
                        "Implement output encoding and Content Security Policy (CSP). Validate and sanitize all user inputs."));
                    log("🚨 HIGH: XSS vulnerability found!");
                    break;
                }
                
                Thread.sleep(150);
            } catch (Exception e) {
                log("⚠️  XSS test error: " + e.getMessage());
            }
        }
    }
    
    private void testPathTraversal(String baseUrl, List<Vulnerability> vulnerabilities) throws Exception {
        log("🔍 Testing path traversal vulnerabilities...");
        
        String[] payloads = {"../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", 
                           "%2e%2e%2f%2e%2e%2f%2e%2e%2f", "....//....//....//etc/passwd"};
        
        for (String payload : payloads) {
            try {
                String testUrl = baseUrl + "/file?path=" + payload + "&filename=" + payload;
                HttpURLConnection conn = createConnection(testUrl);
                String responseBody = readResponse(conn);
                
                log("🧪 Path Test: " + payload + " → " + conn.getResponseCode());
                
                if ((responseBody.contains("root:") || responseBody.contains("admin") || 
                     responseBody.contains("localhost") || responseBody.contains("[drivers]")) &&
                    conn.getResponseCode() == 200) {
                    
                    vulnerabilities.add(new Vulnerability("HIGH", "Path Traversal", 
                        testUrl, "Directory traversal vulnerability detected",
                        "Application allows access to files outside intended directory using: " + payload,
                        "Implement proper file access controls and input validation. Use whitelist approach for file access."));
                    log("🚨 HIGH: Path traversal vulnerability found!");
                    break;
                }
                
                Thread.sleep(150);
            } catch (Exception e) {
                log("⚠️  Path traversal test error: " + e.getMessage());
            }
        }
    }
    
    private void testHttpMethods(String baseUrl, List<Vulnerability> vulnerabilities) throws Exception {
        log("🔍 Testing HTTP method security...");
        
        String[] methods = {"DELETE", "PUT", "PATCH", "TRACE", "OPTIONS"};
        
        for (String method : methods) {
            try {
                HttpURLConnection conn = (HttpURLConnection) new URL(baseUrl).openConnection();
                conn.setRequestMethod(method);
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(10000);
                
                int responseCode = conn.getResponseCode();
                log("🧪 HTTP " + method + " → " + responseCode);
                
                if (responseCode == 200 || responseCode == 204) {
                    vulnerabilities.add(new Vulnerability("MEDIUM", "HTTP Method Override", 
                        baseUrl, "Dangerous HTTP method allowed: " + method,
                        method + " method returned successful response (" + responseCode + ")",
                        "Restrict HTTP methods to only those required (typically GET, POST). Disable dangerous methods."));
                    log("⚠️  MEDIUM: " + method + " method allowed");
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                log("⚠️  HTTP method test error: " + e.getMessage());
            }
        }
    }
    
    private void testRateLimiting(String baseUrl, List<Vulnerability> vulnerabilities) throws Exception {
        log("🔍 Testing rate limiting...");
        
        int successfulRequests = 0;
        int totalRequests = 15;
        
        for (int i = 0; i < totalRequests; i++) {
            try {
                HttpURLConnection conn = createConnection(baseUrl);
                if (conn.getResponseCode() == 200) {
                    successfulRequests++;
                }
                Thread.sleep(50);
            } catch (Exception e) {
                break;
            }
        }
        
        log("🧪 Rate Limiting: " + successfulRequests + "/" + totalRequests + " requests succeeded");
        
        if (successfulRequests >= totalRequests - 2) {
            vulnerabilities.add(new Vulnerability("MEDIUM", "Missing Rate Limiting", 
                baseUrl, "No rate limiting detected",
                "Multiple rapid requests succeeded without throttling (" + successfulRequests + "/" + totalRequests + ")",
                "Implement rate limiting to prevent abuse and DoS attacks."));
            log("⚠️  MEDIUM: No rate limiting detected");
        }
    }
    
    private HttpURLConnection createConnection(String url) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(10000);
        conn.setRequestProperty("User-Agent", "VaultScope-Security-Scanner/1.0");
        return conn;
    }
    
    private String readResponse(HttpURLConnection conn) throws Exception {
        StringBuilder response = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                conn.getResponseCode() < 400 ? conn.getInputStream() : conn.getErrorStream()))) {
            String line;
            int maxLines = 100;
            while ((line = reader.readLine()) != null && maxLines-- > 0) {
                response.append(line).append("\n");
                if (response.length() > 10000) break;
            }
        }
        return response.toString();
    }
    
    private int calculateSecurityScore(List<Vulnerability> vulnerabilities) {
        int score = 100;
        for (Vulnerability vuln : vulnerabilities) {
            switch (vuln.severity) {
                case "CRITICAL": score -= 25; break;
                case "HIGH": score -= 15; break;
                case "MEDIUM": score -= 8; break;
                case "LOW": score -= 3; break;
            }
        }
        return Math.max(0, score);
    }
    
    private String getSecurityGrade(int score) {
        if (score >= 90) return "A";
        if (score >= 80) return "B";
        if (score >= 70) return "C";
        if (score >= 60) return "D";
        return "F";
    }
    
    private void showVulnerabilityDetails(Vulnerability vuln) {
        String details = String.format(
            "🔴 VULNERABILITY DETAILS\n" +
            "═══════════════════════════════════════\n\n" +
            "Severity: %s\n" +
            "Type: %s\n" +
            "Endpoint: %s\n\n" +
            "Description:\n%s\n\n" +
            "Technical Details:\n%s\n\n" +
            "💡 Recommendation:\n%s\n",
            vuln.severity, vuln.type, vuln.endpoint, 
            vuln.description, vuln.details, vuln.recommendation
        );
        detailsArea.setText(details);
        detailsArea.setCaretPosition(0);
    }
    
    private void exportReport(ActionEvent e) {
        if (currentResults.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No scan results to export!", "Export Error", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        try {
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
            String filename = "VaultScope_Report_" + timestamp + ".html";
            
            StringBuilder html = new StringBuilder();
            html.append("<!DOCTYPE html><html><head><title>VaultScope Security Report</title>");
            html.append("<style>body{font-family:Arial,sans-serif;margin:40px;background:#f5f5f5;}");
            html.append(".header{background:#007acc;color:white;padding:20px;border-radius:8px;}");
            html.append(".summary{background:white;padding:20px;margin:20px 0;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1);}");
            html.append(".vuln{background:white;margin:10px 0;padding:15px;border-left:5px solid;border-radius:4px;}");
            html.append(".critical{border-left-color:#dc3545;}.high{border-left-color:#fd7e14;}");
            html.append(".medium{border-left-color:#ffc107;}.low{border-left-color:#28a745;}");
            html.append(".badge{padding:4px 8px;border-radius:12px;color:white;font-size:12px;font-weight:bold;}");
            html.append(".badge.critical{background:#dc3545;}.badge.high{background:#fd7e14;}");
            html.append(".badge.medium{background:#ffc107;color:#333;}.badge.low{background:#28a745;}</style></head><body>");
            
            html.append("<div class='header'><h1>🛡️ VaultScope Security Assessment Report</h1>");
            html.append("<p>Generated: ").append(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))).append("</p>");
            html.append("<p>Target: ").append(urlField.getText()).append("</p></div>");
            
            int score = calculateSecurityScore(currentResults);
            html.append("<div class='summary'><h2>Executive Summary</h2>");
            html.append("<p><strong>Security Score: ").append(score).append("/100 (").append(getSecurityGrade(score)).append(")</strong></p>");
            html.append("<p><strong>Total Issues Found: ").append(currentResults.size()).append("</strong></p>");
            
            long critical = currentResults.stream().filter(v -> "CRITICAL".equals(v.severity)).count();
            long high = currentResults.stream().filter(v -> "HIGH".equals(v.severity)).count();
            long medium = currentResults.stream().filter(v -> "MEDIUM".equals(v.severity)).count();
            long low = currentResults.stream().filter(v -> "LOW".equals(v.severity)).count();
            
            html.append("<p>Critical: ").append(critical).append(" | High: ").append(high);
            html.append(" | Medium: ").append(medium).append(" | Low: ").append(low).append("</p></div>");
            
            html.append("<div class='summary'><h2>Vulnerability Details</h2>");
            for (Vulnerability vuln : currentResults) {
                html.append("<div class='vuln ").append(vuln.severity.toLowerCase()).append("'>");
                html.append("<h3>").append(vuln.type).append(" <span class='badge ").append(vuln.severity.toLowerCase()).append("'>").append(vuln.severity).append("</span></h3>");
                html.append("<p><strong>Endpoint:</strong> ").append(vuln.endpoint).append("</p>");
                html.append("<p><strong>Description:</strong> ").append(vuln.description).append("</p>");
                html.append("<p><strong>Details:</strong> ").append(vuln.details).append("</p>");
                html.append("<p><strong>Recommendation:</strong> ").append(vuln.recommendation).append("</p></div>");
            }
            html.append("</div>");
            
            html.append("<div class='summary'><p><em>Report generated by VaultScope - Enterprise API Security Assessment Tool</em></p>");
            html.append("<p>Author: CPTCR | <a href='https://cptcr.dev'>cptcr.dev</a> | <a href='https://github.com/cptcr'>GitHub</a></p></div>");
            html.append("</body></html>");
            
            try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
                writer.println(html.toString());
            }
            
            JOptionPane.showMessageDialog(this, 
                "✅ Report exported successfully!\n\nFile: " + filename + "\n\nThe report has been saved in the current directory.",
                "Export Complete", JOptionPane.INFORMATION_MESSAGE);
            
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "❌ Export failed: " + ex.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
        }
    }
    
    private void toggleTheme(ActionEvent e) {
        isDarkTheme = !isDarkTheme;
        applyTheme();
        themeButton.setText(isDarkTheme ? "☀️ Light Theme" : "🌙 Dark Theme");
    }
    
    private void applyTheme() {
        Color bgColor = isDarkTheme ? new Color(45, 45, 45) : Color.WHITE;
        Color textColor = isDarkTheme ? Color.WHITE : Color.BLACK;
        Color panelColor = isDarkTheme ? new Color(60, 60, 60) : new Color(245, 245, 245);
        
        getContentPane().setBackground(bgColor);
        
        setComponentColors(this, bgColor, textColor, panelColor);
        
        if (isDarkTheme) {
            logArea.setBackground(Color.BLACK);
            logArea.setForeground(new Color(0, 255, 0));
        } else {
            logArea.setBackground(Color.WHITE);
            logArea.setForeground(Color.BLACK);
        }
        
        repaint();
    }
    
    private void setComponentColors(Container container, Color bg, Color fg, Color panel) {
        for (Component component : container.getComponents()) {
            if (component instanceof JPanel) {
                component.setBackground(panel);
                setComponentColors((Container) component, bg, fg, panel);
            } else if (component instanceof JLabel) {
                component.setForeground(fg);
            } else if (component instanceof JTextField || component instanceof JTextArea) {
                component.setBackground(bg);
                component.setForeground(fg);
            } else if (component instanceof JTable) {
                component.setBackground(bg);
                component.setForeground(fg);
            } else if (component instanceof Container) {
                setComponentColors((Container) component, bg, fg, panel);
            }
        }
    }
    
    private void log(String message) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }
    
    static class Vulnerability {
        String severity, type, endpoint, description, details, recommendation;
        
        Vulnerability(String severity, String type, String endpoint, String description, String details, String recommendation) {
            this.severity = severity;
            this.type = type;
            this.endpoint = endpoint;
            this.description = description;
            this.details = details;
            this.recommendation = recommendation;
        }
    }
    
    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeel());
        } catch (Exception e) {
            // Use default
        }
        
        SwingUtilities.invokeLater(() -> {
            new VaultScope().setVisible(true);
        });
    }
}