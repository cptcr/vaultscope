package dev.cptcr.vaultscope;

import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.layout.VBox;

import java.net.URL;
import java.util.ResourceBundle;

public class SplashScreenController implements Initializable {
    
    @FXML
    private VBox rootPane;
    
    @FXML
    private Label statusLabel;
    
    @FXML
    private ProgressBar loadingProgress;
    
    @FXML
    private Label versionLabel;
    
    private Runnable onLoadComplete;
    
    @Override
    public void initialize(URL location, ResourceBundle resources) {
        versionLabel.setText("Version 1.0.0");
        startLoading();
    }
    
    public void setOnLoadComplete(Runnable onLoadComplete) {
        this.onLoadComplete = onLoadComplete;
    }
    
    private void startLoading() {
        Task<Void> loadingTask = new Task<Void>() {
            @Override
            protected Void call() throws Exception {
                String[] loadingSteps = {
                    "Initializing VaultScope...",
                    "Loading security modules...",
                    "Configuring authentication handlers...",
                    "Setting up vulnerability database...",
                    "Initializing UI components...",
                    "Loading themes...",
                    "Starting security scanner...",
                    "Ready to launch!"
                };
                
                for (int i = 0; i < loadingSteps.length; i++) {
                    final int step = i;
                    Platform.runLater(() -> {
                        statusLabel.setText(loadingSteps[step]);
                        loadingProgress.setProgress((double) (step + 1) / loadingSteps.length);
                    });
                    
                    // Simulate loading time
                    Thread.sleep(300 + (int)(Math.random() * 200));
                }
                
                return null;
            }
            
            @Override
            protected void succeeded() {
                Platform.runLater(() -> {
                    if (onLoadComplete != null) {
                        onLoadComplete.run();
                    }
                });
            }
        };
        
        new Thread(loadingTask).start();
    }
}