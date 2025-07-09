package dev.cptcr.vaultscope.controller;

import dev.cptcr.vaultscope.model.AuthenticationConfig;
import dev.cptcr.vaultscope.model.SecurityResult;
import dev.cptcr.vaultscope.model.Vulnerability;
import dev.cptcr.vaultscope.service.ReportService;
import dev.cptcr.vaultscope.service.SecurityScanner;
import dev.cptcr.vaultscope.service.UrlValidator;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.geometry.Insets;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;

import java.net.URL;
import java.util.ResourceBundle;

public class MainController implements Initializable {

    @FXML private TextField targetUrlField;
    @FXML private Button scanButton;
    @FXML private Button exportJsonButton;
    @FXML private Button exportHtmlButton;
    @FXML private Button toggleThemeButton;
    @FXML private ProgressBar scanProgress;
    @FXML private Label statusLabel;
    @FXML private Label securityScoreLabel;
    @FXML private TableView<Vulnerability> vulnerabilityTable;
    @FXML private TableColumn<Vulnerability, String> severityColumn;
    @FXML private TableColumn<Vulnerability, String> typeColumn;
    @FXML private TableColumn<Vulnerability, String> endpointColumn;
    @FXML private TableColumn<Vulnerability, String> descriptionColumn;
    @FXML private TextArea trafficLogArea;
    @FXML private TextArea vulnerabilityDetailsArea;
    @FXML private VBox rootPane;
    @FXML private ComboBox<String> authTypeComboBox;
    @FXML private VBox authConfigContainer;

    private SecurityScanner securityScanner;
    private ReportService reportService;
    private UrlValidator urlValidator;
    private SecurityResult currentResult;
    private ObservableList<Vulnerability> vulnerabilities;
    private boolean isDarkTheme = false;
    private AuthenticationConfig authConfig;
    private TextField usernameField, passwordField, tokenField, apiKeyField, apiKeyHeaderField;
    private TextField clientIdField, clientSecretField, authUrlField, tokenUrlField, scopeField;
    private CheckBox testWeakSecretsBox, testAlgorithmConfusionBox, testTokenExpirationBox;
    private CheckBox testSessionFixationBox, testPrivilegeEscalationBox;

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        securityScanner = new SecurityScanner();
        reportService = new ReportService();
        urlValidator = new UrlValidator();
        vulnerabilities = FXCollections.observableArrayList();
        
        authConfig = new AuthenticationConfig();
        
        setupTable();
        setupAuthenticationUI();
        setupEventHandlers();
        updateButtonStates();
        
        targetUrlField.setText("localhost:8080");
        vulnerabilityDetailsArea.setText("Select a vulnerability to view details");
        trafficLogArea.setText("Traffic log will appear here during scanning");
    }

    private void setupTable() {
        severityColumn.setCellValueFactory(new PropertyValueFactory<>("severity"));
        typeColumn.setCellValueFactory(new PropertyValueFactory<>("type"));
        endpointColumn.setCellValueFactory(new PropertyValueFactory<>("endpoint"));
        descriptionColumn.setCellValueFactory(new PropertyValueFactory<>("description"));
        
        vulnerabilityTable.setItems(vulnerabilities);
        
        vulnerabilityTable.getSelectionModel().selectedItemProperty().addListener(
            (observable, oldValue, newValue) -> {
                if (newValue != null) {
                    showVulnerabilityDetails(newValue);
                }
            });
    }

    private void setupEventHandlers() {
        scanButton.setOnAction(e -> startScan());
        exportJsonButton.setOnAction(e -> exportJson());
        exportHtmlButton.setOnAction(e -> exportHtml());
        toggleThemeButton.setOnAction(e -> toggleTheme());
        
        targetUrlField.textProperty().addListener((observable, oldValue, newValue) -> {
            updateButtonStates();
        });
        
        authTypeComboBox.setOnAction(e -> {
            String selectedType = authTypeComboBox.getValue();
            if (selectedType != null) {
                updateAuthConfig(selectedType);
                updateAuthUI(selectedType);
            }
        });
    }
    
    private void setupAuthenticationUI() {
        authTypeComboBox.setItems(FXCollections.observableArrayList(
            "None", "Basic Auth", "Bearer Token", "JWT", "API Key", "OAuth 2.0", "Custom"
        ));
        authTypeComboBox.setValue("None");
        
        authConfigContainer.getChildren().clear();
    }
    
    private void updateAuthConfig(String authType) {
        switch (authType) {
            case "None" -> authConfig.setAuthType(AuthenticationConfig.AuthType.NONE);
            case "Basic Auth" -> authConfig.setAuthType(AuthenticationConfig.AuthType.BASIC);
            case "Bearer Token" -> authConfig.setAuthType(AuthenticationConfig.AuthType.BEARER);
            case "JWT" -> authConfig.setAuthType(AuthenticationConfig.AuthType.JWT);
            case "API Key" -> authConfig.setAuthType(AuthenticationConfig.AuthType.API_KEY);
            case "OAuth 2.0" -> authConfig.setAuthType(AuthenticationConfig.AuthType.OAUTH2);
            case "Custom" -> authConfig.setAuthType(AuthenticationConfig.AuthType.CUSTOM);
        }
    }
    
    private void updateAuthUI(String authType) {
        authConfigContainer.getChildren().clear();
        
        switch (authType) {
            case "None" -> {
                Label infoLabel = new Label("No authentication will be used during testing.");
                infoLabel.setStyle("-fx-text-fill: #666666; -fx-font-size: 11px;");
                authConfigContainer.getChildren().add(infoLabel);
            }
            
            case "Basic Auth" -> {
                usernameField = new TextField();
                usernameField.setPromptText("Username");
                passwordField = new TextField();
                passwordField.setPromptText("Password");
                
                usernameField.textProperty().addListener((obs, old, val) -> authConfig.setUsername(val));
                passwordField.textProperty().addListener((obs, old, val) -> authConfig.setPassword(val));
                
                authConfigContainer.getChildren().addAll(
                    new Label("Username:"), usernameField,
                    new Label("Password:"), passwordField
                );
            }
            
            case "Bearer Token" -> {
                tokenField = new TextField();
                tokenField.setPromptText("Bearer Token");
                tokenField.textProperty().addListener((obs, old, val) -> authConfig.setToken(val));
                
                authConfigContainer.getChildren().addAll(
                    new Label("Token:"), tokenField
                );
            }
            
            case "JWT" -> {
                tokenField = new TextField();
                tokenField.setPromptText("JWT Token");
                tokenField.textProperty().addListener((obs, old, val) -> authConfig.setToken(val));
                
                TextField jwtSecretField = new TextField();
                jwtSecretField.setPromptText("JWT Secret (for testing)");
                jwtSecretField.textProperty().addListener((obs, old, val) -> authConfig.setJwtSecret(val));
                
                testWeakSecretsBox = new CheckBox("Test Weak Secrets");
                testWeakSecretsBox.setSelected(true);
                testWeakSecretsBox.selectedProperty().addListener((obs, old, val) -> authConfig.setTestWeakSecrets(val));
                
                testAlgorithmConfusionBox = new CheckBox("Test Algorithm Confusion");
                testAlgorithmConfusionBox.setSelected(true);
                testAlgorithmConfusionBox.selectedProperty().addListener((obs, old, val) -> authConfig.setTestAlgorithmConfusion(val));
                
                testTokenExpirationBox = new CheckBox("Test Token Expiration");
                testTokenExpirationBox.setSelected(true);
                testTokenExpirationBox.selectedProperty().addListener((obs, old, val) -> authConfig.setTestTokenExpiration(val));
                
                authConfigContainer.getChildren().addAll(
                    new Label("JWT Token:"), tokenField,
                    new Label("JWT Secret (optional):"), jwtSecretField,
                    new Label("JWT Tests:"), testWeakSecretsBox, testAlgorithmConfusionBox, testTokenExpirationBox
                );
            }
            
            case "API Key" -> {
                apiKeyField = new TextField();
                apiKeyField.setPromptText("API Key");
                apiKeyField.textProperty().addListener((obs, old, val) -> authConfig.setApiKey(val));
                
                apiKeyHeaderField = new TextField();
                apiKeyHeaderField.setPromptText("X-API-Key");
                apiKeyHeaderField.setText("X-API-Key");
                apiKeyHeaderField.textProperty().addListener((obs, old, val) -> authConfig.setApiKeyHeader(val));
                
                authConfigContainer.getChildren().addAll(
                    new Label("API Key:"), apiKeyField,
                    new Label("Header Name:"), apiKeyHeaderField
                );
            }
            
            case "OAuth 2.0" -> {
                clientIdField = new TextField();
                clientIdField.setPromptText("Client ID");
                clientIdField.textProperty().addListener((obs, old, val) -> authConfig.setClientId(val));
                
                clientSecretField = new TextField();
                clientSecretField.setPromptText("Client Secret");
                clientSecretField.textProperty().addListener((obs, old, val) -> authConfig.setClientSecret(val));
                
                authUrlField = new TextField();
                authUrlField.setPromptText("Authorization URL");
                authUrlField.textProperty().addListener((obs, old, val) -> authConfig.setAuthorizationUrl(val));
                
                tokenUrlField = new TextField();
                tokenUrlField.setPromptText("Token URL");
                tokenUrlField.textProperty().addListener((obs, old, val) -> authConfig.setTokenUrl(val));
                
                scopeField = new TextField();
                scopeField.setPromptText("Scope (optional)");
                scopeField.textProperty().addListener((obs, old, val) -> authConfig.setScope(val));
                
                authConfigContainer.getChildren().addAll(
                    new Label("Client ID:"), clientIdField,
                    new Label("Client Secret:"), clientSecretField,
                    new Label("Authorization URL:"), authUrlField,
                    new Label("Token URL:"), tokenUrlField,
                    new Label("Scope:"), scopeField
                );
            }
            
            case "Custom" -> {
                Label customLabel = new Label("Custom Headers:");
                TextField customHeaderField = new TextField();
                customHeaderField.setPromptText("Header-Name: Header-Value");
                
                Button addHeaderButton = new Button("Add Header");
                addHeaderButton.setOnAction(e -> {
                    String headerText = customHeaderField.getText().trim();
                    if (headerText.contains(":")) {
                        String[] parts = headerText.split(":", 2);
                        authConfig.getCustomHeaders().put(parts[0].trim(), parts[1].trim());
                        customHeaderField.clear();
                    }
                });
                
                HBox headerBox = new HBox(10, customHeaderField, addHeaderButton);
                
                authConfigContainer.getChildren().addAll(
                    customLabel, headerBox
                );
            }
        }
        
        if (!authType.equals("None")) {
            Label advancedLabel = new Label("Advanced Tests:");
            advancedLabel.setStyle("-fx-font-weight: bold; -fx-padding: 10 0 5 0;");
            
            testSessionFixationBox = new CheckBox("Test Session Fixation");
            testSessionFixationBox.setSelected(true);
            testSessionFixationBox.selectedProperty().addListener((obs, old, val) -> authConfig.setTestSessionFixation(val));
            
            testPrivilegeEscalationBox = new CheckBox("Test Privilege Escalation");
            testPrivilegeEscalationBox.setSelected(true);
            testPrivilegeEscalationBox.selectedProperty().addListener((obs, old, val) -> authConfig.setTestPrivilegeEscalation(val));
            
            authConfigContainer.getChildren().addAll(
                advancedLabel, testSessionFixationBox, testPrivilegeEscalationBox
            );
        }
    }

    private void startScan() {
        String targetUrl = targetUrlField.getText().trim();
        
        if (!urlValidator.isValidLocalhostUrl(targetUrl)) {
            showAlert(Alert.AlertType.ERROR, "Invalid URL", 
                "Please enter a valid localhost URL\n\nExamples:\n• localhost:8080\n• 127.0.0.1:3000\n• http://localhost/api");
            return;
        }

        scanButton.setDisabled(true);
        scanProgress.setVisible(true);
        statusLabel.setText("Initializing security scan...");
        vulnerabilities.clear();
        trafficLogArea.clear();
        vulnerabilityDetailsArea.clear();
        securityScoreLabel.setText("Score: --");

        Task<SecurityResult> scanTask = new Task<SecurityResult>() {
            @Override
            protected SecurityResult call() throws Exception {
                return securityScanner.performSecurityScan(targetUrl, authConfig,
                    (message) -> Platform.runLater(() -> {
                        trafficLogArea.appendText(message + "\n");
                        trafficLogArea.setScrollTop(Double.MAX_VALUE);
                    }),
                    (progress) -> Platform.runLater(() -> {
                        scanProgress.setProgress(progress);
                        if (progress < 1.0) {
                            statusLabel.setText(String.format("Scanning... %.0f%%", progress * 100));
                        }
                    })
                );
            }

            @Override
            protected void succeeded() {
                Platform.runLater(() -> {
                    currentResult = getValue();
                    vulnerabilities.addAll(currentResult.getVulnerabilities());
                    
                    int score = currentResult.getSecurityScore();
                    String grade = getGradeFromScore(score);
                    securityScoreLabel.setText(String.format("Score: %d/100 (%s)", score, grade));
                    
                    statusLabel.setText(String.format("Scan completed - Found %d vulnerabilities", vulnerabilities.size()));
                    scanProgress.setVisible(false);
                    scanButton.setDisabled(false);
                    updateButtonStates();
                    
                    if (vulnerabilities.isEmpty()) {
                        vulnerabilityDetailsArea.setText("🎉 Excellent!\n\nNo security vulnerabilities detected!\nYour API appears to be well-secured.");
                    } else {
                        vulnerabilityDetailsArea.setText("Security scan completed.\nSelect a vulnerability from the table above to view details.");
                    }
                });
            }

            @Override
            protected void failed() {
                Platform.runLater(() -> {
                    statusLabel.setText("Scan failed");
                    scanProgress.setVisible(false);
                    scanButton.setDisabled(false);
                    showAlert(Alert.AlertType.ERROR, "Scan Error", 
                        "Failed to complete security scan:\n" + getException().getMessage());
                });
            }
        };

        new Thread(scanTask).start();
    }

    private void exportJson() {
        if (currentResult != null) {
            try {
                String filename = reportService.exportJsonReport(currentResult);
                showAlert(Alert.AlertType.INFORMATION, "Export Successful", 
                    "JSON report exported successfully!\n\nFile: " + filename);
            } catch (Exception e) {
                showAlert(Alert.AlertType.ERROR, "Export Error", 
                    "Failed to export JSON report:\n" + e.getMessage());
            }
        }
    }

    private void exportHtml() {
        if (currentResult != null) {
            try {
                String filename = reportService.exportHtmlReport(currentResult);
                showAlert(Alert.AlertType.INFORMATION, "Export Successful", 
                    "HTML report exported successfully!\n\nFile: " + filename);
            } catch (Exception e) {
                showAlert(Alert.AlertType.ERROR, "Export Error", 
                    "Failed to export HTML report:\n" + e.getMessage());
            }
        }
    }

    private void toggleTheme() {
        isDarkTheme = !isDarkTheme;
        if (isDarkTheme) {
            rootPane.getScene().getStylesheets().clear();
            rootPane.getScene().getStylesheets().add(getClass().getResource("/css/dark-theme.css").toExternalForm());
            toggleThemeButton.setText("☀️ Light Theme");
        } else {
            rootPane.getScene().getStylesheets().clear();
            rootPane.getScene().getStylesheets().add(getClass().getResource("/css/styles.css").toExternalForm());
            toggleThemeButton.setText("🌙 Dark Theme");
        }
    }

    private void updateButtonStates() {
        boolean hasValidUrl = urlValidator.isValidLocalhostUrl(targetUrlField.getText().trim());
        scanButton.setDisabled(!hasValidUrl);
        
        boolean hasResults = currentResult != null && !currentResult.getVulnerabilities().isEmpty();
        exportJsonButton.setDisabled(currentResult == null);
        exportHtmlButton.setDisabled(currentResult == null);
    }

    private void showVulnerabilityDetails(Vulnerability vuln) {
        String details = String.format(
            "🔍 VULNERABILITY DETAILS\n" +
            "═══════════════════════════════════════\n\n" +
            "Severity: %s\n" +
            "Type: %s\n" +
            "Endpoint: %s\n\n" +
            "Description:\n%s\n\n" +
            "Technical Details:\n%s\n\n" +
            "💡 Recommendation:\n%s\n",
            vuln.getSeverity(), vuln.getType(), vuln.getEndpoint(),
            vuln.getDescription(), vuln.getDetails(), vuln.getRecommendation()
        );
        vulnerabilityDetailsArea.setText(details);
        vulnerabilityDetailsArea.setScrollTop(0);
    }

    private String getGradeFromScore(int score) {
        if (score >= 90) return "A";
        if (score >= 80) return "B";
        if (score >= 70) return "C";
        if (score >= 60) return "D";
        return "F";
    }

    private void showAlert(Alert.AlertType type, String title, String message) {
        Alert alert = new Alert(type);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }
}