package dev.cptcr.vaultscope.controller;

import dev.cptcr.vaultscope.model.AuthenticationConfig;
import dev.cptcr.vaultscope.model.SecurityResult;
import dev.cptcr.vaultscope.model.Vulnerability;
import dev.cptcr.vaultscope.service.AuthenticationTester;
import dev.cptcr.vaultscope.service.SecurityScanner;
import dev.cptcr.vaultscope.util.DatabaseManager;
import dev.cptcr.vaultscope.util.Logger;
import dev.cptcr.vaultscope.util.SecurityValidator;
import dev.cptcr.vaultscope.util.ThemeManager;
import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URL;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ResourceBundle;

public class EnhancedMainController implements Initializable {

    @FXML private BorderPane rootPane;
    @FXML private TextField targetUrlField;
    @FXML private ComboBox<String> authTypeComboBox;
    @FXML private VBox authConfigContainer;
    @FXML private Button scanButton;
    @FXML private Label securityScoreLabel;
    @FXML private Button exportJsonButton;
    @FXML private Button exportHtmlButton;
    @FXML private Button toggleThemeButton;
    @FXML private ProgressBar scanProgress;
    @FXML private Label statusLabel;
    @FXML private TableView<Vulnerability> vulnerabilityTable;
    @FXML private TableColumn<Vulnerability, String> severityColumn;
    @FXML private TableColumn<Vulnerability, String> typeColumn;
    @FXML private TableColumn<Vulnerability, String> endpointColumn;
    @FXML private TableColumn<Vulnerability, String> descriptionColumn;
    @FXML private TextArea vulnerabilityDetailsArea;
    @FXML private TextArea trafficLogArea;

    private SecurityScanner securityScanner;
    private AuthenticationTester authenticationTester;
    private SecurityResult lastScanResult;
    private TextField apiKeyField;
    private TextField jwtTokenField;
    private TextField usernameField;
    private PasswordField passwordField;
    private TextField customHeaderNameField;
    private TextField customHeaderValueField;

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        Logger.getInstance().info("UI", "Initializing enhanced main controller");
        
        setupUI();
        setupEventHandlers();
        setupTableColumns();
        setupLogging();
        
        // Initialize services
        securityScanner = new SecurityScanner();
        authenticationTester = new AuthenticationTester();
        
        // Set initial status
        statusLabel.setText("🛡️ VaultScope Enterprise Ready - Localhost Security Testing");
        updateThemeButton();
        
        Logger.getInstance().info("UI", "Enhanced main controller initialized successfully");
    }

    private void setupUI() {
        // Setup authentication type combo box
        authTypeComboBox.getItems().addAll(
            "None", 
            "API Key", 
            "JWT Bearer Token", 
            "Basic Authentication", 
            "Custom Header",
            "OAuth 2.0"
        );
        
        // Setup authentication configuration container
        authTypeComboBox.setOnAction(e -> updateAuthConfiguration());
        
        // Setup initial state
        scanButton.setDisable(false);
        exportJsonButton.setDisable(true);
        exportHtmlButton.setDisable(true);
        scanProgress.setVisible(false);
        
        // Set tooltips
        targetUrlField.setTooltip(new Tooltip("Enter localhost URL (e.g., localhost:8080/api)"));
        scanButton.setTooltip(new Tooltip("Start comprehensive security assessment"));
        toggleThemeButton.setTooltip(new Tooltip("Switch between light and dark themes"));
    }

    private void setupEventHandlers() {
        // Target URL validation
        targetUrlField.textProperty().addListener((obs, oldVal, newVal) -> {
            validateTargetUrl(newVal);
        });
        
        // Scan button
        scanButton.setOnAction(e -> startSecurityScan());
        
        // Export buttons
        exportJsonButton.setOnAction(e -> exportToJson());
        exportHtmlButton.setOnAction(e -> exportToHtml());
        
        // Theme toggle
        toggleThemeButton.setOnAction(e -> toggleTheme());
    }

    private void setupTableColumns() {
        severityColumn.setCellValueFactory(new PropertyValueFactory<>("severity"));
        typeColumn.setCellValueFactory(new PropertyValueFactory<>("type"));
        endpointColumn.setCellValueFactory(new PropertyValueFactory<>("endpoint"));
        descriptionColumn.setCellValueFactory(new PropertyValueFactory<>("description"));
        
        // Custom severity cell factory for color coding
        severityColumn.setCellFactory(column -> new TableCell<Vulnerability, String>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                    setStyle("");
                } else {
                    setText(item);
                    getStyleClass().removeAll("severity-badge", "critical", "high", "medium", "low", "info");
                    getStyleClass().addAll("severity-badge", item.toLowerCase());
                }
            }
        });
        
        // Table selection listener
        vulnerabilityTable.getSelectionModel().selectedItemProperty().addListener((obs, oldVal, newVal) -> {
            if (newVal != null) {
                showVulnerabilityDetails(newVal);
            }
        });
    }

    private void setupLogging() {
        Logger.getInstance().addListener(entry -> {
            Platform.runLater(() -> {
                String logLine = String.format("[%s] %s %s: %s%n",
                    entry.getTimestamp().format(DateTimeFormatter.ofPattern("HH:mm:ss")),
                    entry.getLevel().getEmoji(),
                    entry.getCategory(),
                    entry.getMessage()
                );
                trafficLogArea.appendText(logLine);
            });
        });
    }

    private void updateAuthConfiguration() {
        authConfigContainer.getChildren().clear();
        
        String selectedAuth = authTypeComboBox.getValue();
        if (selectedAuth == null) return;
        
        switch (selectedAuth) {
            case "API Key":
                apiKeyField = new TextField();
                apiKeyField.setPromptText("Enter API Key");
                apiKeyField.getStyleClass().add("url-field");
                authConfigContainer.getChildren().add(new Label("API Key:"));
                authConfigContainer.getChildren().add(apiKeyField);
                
                apiKeyField.textProperty().addListener((obs, oldVal, newVal) -> {
                    validateApiKey(newVal);
                });
                break;
                
            case "JWT Bearer Token":
                jwtTokenField = new TextField();
                jwtTokenField.setPromptText("Enter JWT Token");
                jwtTokenField.getStyleClass().add("url-field");
                authConfigContainer.getChildren().add(new Label("JWT Token:"));
                authConfigContainer.getChildren().add(jwtTokenField);
                
                jwtTokenField.textProperty().addListener((obs, oldVal, newVal) -> {
                    validateJWT(newVal);
                });
                break;
                
            case "Basic Authentication":
                usernameField = new TextField();
                usernameField.setPromptText("Username");
                usernameField.getStyleClass().add("url-field");
                
                passwordField = new PasswordField();
                passwordField.setPromptText("Password");
                passwordField.getStyleClass().add("url-field");
                
                authConfigContainer.getChildren().addAll(
                    new Label("Username:"), usernameField,
                    new Label("Password:"), passwordField
                );
                break;
                
            case "Custom Header":
                customHeaderNameField = new TextField();
                customHeaderNameField.setPromptText("Header Name");
                customHeaderNameField.getStyleClass().add("url-field");
                
                customHeaderValueField = new TextField();
                customHeaderValueField.setPromptText("Header Value");
                customHeaderValueField.getStyleClass().add("url-field");
                
                authConfigContainer.getChildren().addAll(
                    new Label("Header Name:"), customHeaderNameField,
                    new Label("Header Value:"), customHeaderValueField
                );
                break;
        }
    }

    private void validateTargetUrl(String url) {
        if (url == null || url.trim().isEmpty()) {
            statusLabel.setText("⚠️ Please enter a target URL");
            return;
        }
        
        SecurityValidator.ValidationResult result = SecurityValidator.validateTargetUrl(url);
        
        Platform.runLater(() -> {
            switch (result.getSeverity()) {
                case INFO:
                    statusLabel.setText(result.getMessage());
                    statusLabel.getStyleClass().removeAll("error", "warning");
                    statusLabel.getStyleClass().add("success");
                    break;
                case WARNING:
                    statusLabel.setText(result.getMessage());
                    statusLabel.getStyleClass().removeAll("error", "success");
                    statusLabel.getStyleClass().add("warning");
                    break;
                case ERROR:
                case CRITICAL:
                    statusLabel.setText(result.getMessage());
                    statusLabel.getStyleClass().removeAll("success", "warning");
                    statusLabel.getStyleClass().add("error");
                    break;
            }
            
            scanButton.setDisable(!result.isValid());
        });
    }

    private void validateApiKey(String apiKey) {
        if (apiKey == null || apiKey.trim().isEmpty()) return;
        
        SecurityValidator.ValidationResult result = SecurityValidator.validateApiKey(apiKey);
        Logger.getInstance().log(
            result.isValid() ? Logger.Level.INFO : Logger.Level.WARNING,
            "Validation",
            "API Key validation: " + result.getMessage()
        );
    }

    private void validateJWT(String jwt) {
        if (jwt == null || jwt.trim().isEmpty()) return;
        
        SecurityValidator.ValidationResult result = SecurityValidator.validateJWT(jwt);
        Logger.getInstance().log(
            result.isValid() ? Logger.Level.INFO : Logger.Level.WARNING,
            "Validation",
            "JWT validation: " + result.getMessage()
        );
    }

    private void startSecurityScan() {
        String targetUrl = targetUrlField.getText().trim();
        
        // Final validation
        SecurityValidator.ValidationResult urlValidation = SecurityValidator.validateTargetUrl(targetUrl);
        if (!urlValidation.isValid()) {
            showAlert("Invalid Target", urlValidation.getMessage());
            return;
        }
        
        // Log security scan start
        Logger.getInstance().security("Scan", "Starting security scan for: " + targetUrl);
        DatabaseManager.getInstance().logAuditEvent("SECURITY_SCAN_START", "USER_ACTION", targetUrl, 
            "Authentication: " + authTypeComboBox.getValue());
        
        // Prepare authentication configuration
        AuthenticationConfig authConfig = createAuthConfig();
        
        // Start scan in background
        scanButton.setDisable(true);
        scanProgress.setVisible(true);
        statusLabel.setText("🔍 Scanning in progress...");
        
        Task<SecurityResult> scanTask = new Task<SecurityResult>() {
            @Override
            protected SecurityResult call() throws Exception {
                updateProgress(0, 100);
                
                // Simulate comprehensive scanning
                updateMessage("Initializing security scanner...");
                Thread.sleep(500);
                updateProgress(10, 100);
                
                updateMessage("Testing authentication mechanisms...");
                Thread.sleep(1000);
                updateProgress(30, 100);
                
                updateMessage("Scanning for vulnerabilities...");
                SecurityResult result = securityScanner.scanTarget(targetUrl, authConfig);
                updateProgress(70, 100);
                
                updateMessage("Analyzing security posture...");
                Thread.sleep(500);
                updateProgress(90, 100);
                
                updateMessage("Generating security report...");
                Thread.sleep(300);
                updateProgress(100, 100);
                
                return result;
            }
        };
        
        scanTask.setOnSucceeded(e -> {
            lastScanResult = scanTask.getValue();
            displayScanResults(lastScanResult);
            
            // Save to database
            DatabaseManager.getInstance().saveScanSession(targetUrl, authTypeComboBox.getValue(), lastScanResult);
            
            // Log completion
            Logger.getInstance().security("Scan", "Security scan completed successfully");
            DatabaseManager.getInstance().logAuditEvent("SECURITY_SCAN_COMPLETE", "USER_ACTION", targetUrl, 
                "Vulnerabilities found: " + lastScanResult.getVulnerabilities().size());
            
            scanButton.setDisable(false);
            scanProgress.setVisible(false);
            exportJsonButton.setDisable(false);
            exportHtmlButton.setDisable(false);
        });
        
        scanTask.setOnFailed(e -> {
            Throwable exception = scanTask.getException();
            String errorMessage = exception != null ? exception.getMessage() : "Unknown error";
            
            Logger.getInstance().error("Scan", "Security scan failed", errorMessage);
            showAlert("Scan Failed", "Security scan failed: " + errorMessage);
            
            scanButton.setDisable(false);
            scanProgress.setVisible(false);
            statusLabel.setText("❌ Scan failed");
        });
        
        scanProgress.progressProperty().bind(scanTask.progressProperty());
        statusLabel.textProperty().bind(scanTask.messageProperty());
        
        new Thread(scanTask).start();
    }

    private AuthenticationConfig createAuthConfig() {
        String authType = authTypeComboBox.getValue();
        if (authType == null) authType = "None";
        
        AuthenticationConfig config = new AuthenticationConfig();
        config.setType(authType);
        
        switch (authType) {
            case "API Key":
                if (apiKeyField != null) {
                    config.setApiKey(apiKeyField.getText().trim());
                }
                break;
            case "JWT Bearer Token":
                if (jwtTokenField != null) {
                    config.setJwtToken(jwtTokenField.getText().trim());
                }
                break;
            case "Basic Authentication":
                if (usernameField != null && passwordField != null) {
                    config.setUsername(usernameField.getText().trim());
                    config.setPassword(passwordField.getText().trim());
                }
                break;
            case "Custom Header":
                if (customHeaderNameField != null && customHeaderValueField != null) {
                    config.setHeaderName(customHeaderNameField.getText().trim());
                    config.setHeaderValue(customHeaderValueField.getText().trim());
                }
                break;
        }
        
        return config;
    }

    private void displayScanResults(SecurityResult result) {
        // Update vulnerability table
        vulnerabilityTable.getItems().clear();
        vulnerabilityTable.getItems().addAll(result.getVulnerabilities());
        
        // Update security score
        securityScoreLabel.setText(String.format("Score: %d/100", result.getSecurityScore()));
        
        // Update status
        int vulnerabilityCount = result.getVulnerabilities().size();
        if (vulnerabilityCount == 0) {
            statusLabel.setText("✅ No vulnerabilities found");
        } else {
            statusLabel.setText(String.format("⚠️ %d vulnerabilities found", vulnerabilityCount));
        }
    }

    private void showVulnerabilityDetails(Vulnerability vulnerability) {
        StringBuilder details = new StringBuilder();
        details.append("Vulnerability Details\n");
        details.append("=".repeat(50)).append("\n\n");
        details.append("Type: ").append(vulnerability.getType()).append("\n");
        details.append("Severity: ").append(vulnerability.getSeverity()).append("\n");
        details.append("Endpoint: ").append(vulnerability.getEndpoint()).append("\n");
        details.append("CWE ID: ").append(vulnerability.getCweId()).append("\n");
        details.append("CVSS Score: ").append(vulnerability.getCvssScore()).append("\n\n");
        details.append("Description:\n").append(vulnerability.getDescription()).append("\n\n");
        details.append("Remediation:\n").append(vulnerability.getRemediation()).append("\n\n");
        
        if (vulnerability.getEvidence() != null && !vulnerability.getEvidence().isEmpty()) {
            details.append("Evidence:\n").append(vulnerability.getEvidence()).append("\n");
        }
        
        vulnerabilityDetailsArea.setText(details.toString());
    }

    private void exportToJson() {
        if (lastScanResult == null) return;
        
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Export Security Report as JSON");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("JSON files (*.json)", "*.json"));
        fileChooser.setInitialFileName("vaultscope-report-" + 
            LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd-HH-mm-ss")) + ".json");
        
        File file = fileChooser.showSaveDialog(rootPane.getScene().getWindow());
        if (file != null) {
            try {
                String jsonReport = generateJsonReport(lastScanResult);
                try (FileWriter writer = new FileWriter(file)) {
                    writer.write(jsonReport);
                }
                
                Logger.getInstance().info("Export", "JSON report exported successfully to: " + file.getAbsolutePath());
                showAlert("Export Successful", "JSON report exported successfully!");
                
            } catch (IOException e) {
                Logger.getInstance().error("Export", "Failed to export JSON report", e.getMessage());
                showAlert("Export Failed", "Failed to export JSON report: " + e.getMessage());
            }
        }
    }

    private void exportToHtml() {
        if (lastScanResult == null) return;
        
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Export Security Report as HTML");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("HTML files (*.html)", "*.html"));
        fileChooser.setInitialFileName("vaultscope-report-" + 
            LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd-HH-mm-ss")) + ".html");
        
        File file = fileChooser.showSaveDialog(rootPane.getScene().getWindow());
        if (file != null) {
            try {
                String htmlReport = generateHtmlReport(lastScanResult);
                try (FileWriter writer = new FileWriter(file)) {
                    writer.write(htmlReport);
                }
                
                Logger.getInstance().info("Export", "HTML report exported successfully to: " + file.getAbsolutePath());
                showAlert("Export Successful", "HTML report exported successfully!");
                
            } catch (IOException e) {
                Logger.getInstance().error("Export", "Failed to export HTML report", e.getMessage());
                showAlert("Export Failed", "Failed to export HTML report: " + e.getMessage());
            }
        }
    }

    private String generateJsonReport(SecurityResult result) {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"report\": {\n");
        json.append("    \"title\": \"VaultScope Security Assessment Report\",\n");
        json.append("    \"timestamp\": \"").append(LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)).append("\",\n");
        json.append("    \"target\": \"").append(targetUrlField.getText()).append("\",\n");
        json.append("    \"security_score\": ").append(result.getSecurityScore()).append(",\n");
        json.append("    \"vulnerabilities\": [\n");
        
        for (int i = 0; i < result.getVulnerabilities().size(); i++) {
            Vulnerability vuln = result.getVulnerabilities().get(i);
            json.append("      {\n");
            json.append("        \"type\": \"").append(vuln.getType()).append("\",\n");
            json.append("        \"severity\": \"").append(vuln.getSeverity()).append("\",\n");
            json.append("        \"endpoint\": \"").append(vuln.getEndpoint()).append("\",\n");
            json.append("        \"description\": \"").append(vuln.getDescription().replace("\"", "\\\"")).append("\",\n");
            json.append("        \"cwe_id\": \"").append(vuln.getCweId()).append("\",\n");
            json.append("        \"cvss_score\": ").append(vuln.getCvssScore()).append(",\n");
            json.append("        \"remediation\": \"").append(vuln.getRemediation().replace("\"", "\\\"")).append("\"\n");
            json.append("      }");
            if (i < result.getVulnerabilities().size() - 1) {
                json.append(",");
            }
            json.append("\n");
        }
        
        json.append("    ]\n");
        json.append("  }\n");
        json.append("}");
        
        return json.toString();
    }

    private String generateHtmlReport(SecurityResult result) {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>\n<html>\n<head>\n");
        html.append("<title>VaultScope Security Assessment Report</title>\n");
        html.append("<style>\n");
        html.append("body { font-family: Arial, sans-serif; margin: 20px; }\n");
        html.append("h1 { color: #673ab7; }\n");
        html.append("h2 { color: #9c27b0; }\n");
        html.append(".critical { color: #d32f2f; font-weight: bold; }\n");
        html.append(".high { color: #f57c00; font-weight: bold; }\n");
        html.append(".medium { color: #fbc02d; font-weight: bold; }\n");
        html.append(".low { color: #388e3c; font-weight: bold; }\n");
        html.append("table { border-collapse: collapse; width: 100%; }\n");
        html.append("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n");
        html.append("th { background-color: #f2f2f2; }\n");
        html.append("</style>\n");
        html.append("</head>\n<body>\n");
        
        html.append("<h1>🛡️ VaultScope Security Assessment Report</h1>\n");
        html.append("<p><strong>Generated:</strong> ").append(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))).append("</p>\n");
        html.append("<p><strong>Target:</strong> ").append(targetUrlField.getText()).append("</p>\n");
        html.append("<p><strong>Security Score:</strong> ").append(result.getSecurityScore()).append("/100</p>\n");
        
        html.append("<h2>Vulnerabilities Found</h2>\n");
        html.append("<table>\n");
        html.append("<tr><th>Severity</th><th>Type</th><th>Endpoint</th><th>Description</th></tr>\n");
        
        for (Vulnerability vuln : result.getVulnerabilities()) {
            html.append("<tr>\n");
            html.append("<td class=\"").append(vuln.getSeverity().toLowerCase()).append("\">").append(vuln.getSeverity()).append("</td>\n");
            html.append("<td>").append(vuln.getType()).append("</td>\n");
            html.append("<td>").append(vuln.getEndpoint()).append("</td>\n");
            html.append("<td>").append(vuln.getDescription()).append("</td>\n");
            html.append("</tr>\n");
        }
        
        html.append("</table>\n");
        html.append("<p><em>Report generated by VaultScope Enterprise API Security Assessment Tool</em></p>\n");
        html.append("</body>\n</html>");
        
        return html.toString();
    }

    private void toggleTheme() {
        ThemeManager.Theme nextTheme = ThemeManager.getNextTheme();
        ThemeManager.setTheme(nextTheme);
        ThemeManager.applyTheme(rootPane.getScene());
        
        updateThemeButton();
        
        Logger.getInstance().info("UI", "Theme changed to: " + nextTheme.getDisplayName());
    }

    private void updateThemeButton() {
        ThemeManager.Theme currentTheme = ThemeManager.getCurrentTheme();
        switch (currentTheme) {
            case DARK_PURPLE:
                toggleThemeButton.setText("🌙 Dark Theme");
                break;
            case LIGHT_PURPLE:
                toggleThemeButton.setText("☀️ Light Theme");
                break;
            case ENTERPRISE_DARK:
                toggleThemeButton.setText("🏢 Enterprise Theme");
                break;
        }
    }

    private void showAlert(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }
}