package dev.cptcr.vaultscope.controller;

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
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
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

    private SecurityScanner securityScanner;
    private ReportService reportService;
    private UrlValidator urlValidator;
    private SecurityResult currentResult;
    private ObservableList<Vulnerability> vulnerabilities;
    private boolean isDarkTheme = false;

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        securityScanner = new SecurityScanner();
        reportService = new ReportService();
        urlValidator = new UrlValidator();
        vulnerabilities = FXCollections.observableArrayList();
        
        setupTable();
        setupEventHandlers();
        updateButtonStates();
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
                    vulnerabilityDetailsArea.setText(formatVulnerabilityDetails(newValue));
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
    }

    private void startScan() {
        String targetUrl = targetUrlField.getText().trim();
        
        if (!urlValidator.isValidLocalhostUrl(targetUrl)) {
            showAlert("Invalid URL", "Please enter a valid localhost URL (e.g., localhost:8080 or 127.0.0.1:3000)");
            return;
        }

        scanButton.setDisabled(true);
        scanProgress.setVisible(true);
        statusLabel.setText("Scanning...");
        vulnerabilities.clear();
        trafficLogArea.clear();
        vulnerabilityDetailsArea.clear();
        securityScoreLabel.setText("Score: --");

        Task<SecurityResult> scanTask = new Task<SecurityResult>() {
            @Override
            protected SecurityResult call() throws Exception {
                return securityScanner.performSecurityScan(targetUrl, 
                    (message) -> Platform.runLater(() -> {
                        trafficLogArea.appendText(message + "\n");
                        trafficLogArea.setScrollTop(Double.MAX_VALUE);
                    }),
                    (progress) -> Platform.runLater(() -> scanProgress.setProgress(progress))
                );
            }

            @Override
            protected void succeeded() {
                Platform.runLater(() -> {
                    currentResult = getValue();
                    vulnerabilities.addAll(currentResult.getVulnerabilities());
                    securityScoreLabel.setText(String.format("Score: %d/100 (%s)", 
                        currentResult.getSecurityScore(), 
                        getGradeFromScore(currentResult.getSecurityScore())));
                    statusLabel.setText("Scan completed");
                    scanProgress.setVisible(false);
                    scanButton.setDisabled(false);
                    updateButtonStates();
                });
            }

            @Override
            protected void failed() {
                Platform.runLater(() -> {
                    statusLabel.setText("Scan failed");
                    scanProgress.setVisible(false);
                    scanButton.setDisabled(false);
                    showAlert("Scan Error", "Failed to complete security scan: " + getException().getMessage());
                });
            }
        };

        new Thread(scanTask).start();
    }

    private void exportJson() {
        if (currentResult != null) {
            try {
                String filename = reportService.exportJsonReport(currentResult);
                showAlert("Export Successful", "Report exported to: " + filename);
            } catch (Exception e) {
                showAlert("Export Error", "Failed to export JSON report: " + e.getMessage());
            }
        }
    }

    private void exportHtml() {
        if (currentResult != null) {
            try {
                String filename = reportService.exportHtmlReport(currentResult);
                showAlert("Export Successful", "Report exported to: " + filename);
            } catch (Exception e) {
                showAlert("Export Error", "Failed to export HTML report: " + e.getMessage());
            }
        }
    }

    private void toggleTheme() {
        isDarkTheme = !isDarkTheme;
        if (isDarkTheme) {
            rootPane.getScene().getStylesheets().clear();
            rootPane.getScene().getStylesheets().add(getClass().getResource("/css/dark-theme.css").toExternalForm());
            toggleThemeButton.setText("Light Theme");
        } else {
            rootPane.getScene().getStylesheets().clear();
            rootPane.getScene().getStylesheets().add(getClass().getResource("/css/styles.css").toExternalForm());
            toggleThemeButton.setText("Dark Theme");
        }
    }

    private void updateButtonStates() {
        boolean hasValidUrl = urlValidator.isValidLocalhostUrl(targetUrlField.getText().trim());
        scanButton.setDisabled(!hasValidUrl);
        
        boolean hasResults = currentResult != null;
        exportJsonButton.setDisabled(!hasResults);
        exportHtmlButton.setDisabled(!hasResults);
    }

    private String formatVulnerabilityDetails(Vulnerability vulnerability) {
        StringBuilder details = new StringBuilder();
        details.append("Severity: ").append(vulnerability.getSeverity()).append("\n\n");
        details.append("Type: ").append(vulnerability.getType()).append("\n\n");
        details.append("Endpoint: ").append(vulnerability.getEndpoint()).append("\n\n");
        details.append("Description: ").append(vulnerability.getDescription()).append("\n\n");
        details.append("Details: ").append(vulnerability.getDetails()).append("\n\n");
        details.append("Recommendation: ").append(vulnerability.getRecommendation());
        return details.toString();
    }

    private String getGradeFromScore(int score) {
        if (score >= 90) return "A";
        if (score >= 80) return "B";
        if (score >= 70) return "C";
        if (score >= 60) return "D";
        return "F";
    }

    private void showAlert(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }
}