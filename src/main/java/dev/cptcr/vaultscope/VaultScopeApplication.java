package dev.cptcr.vaultscope;

import dev.cptcr.vaultscope.util.DatabaseManager;
import dev.cptcr.vaultscope.util.Logger;
import dev.cptcr.vaultscope.util.ThemeManager;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;
import javafx.stage.StageStyle;

public class VaultScopeApplication extends Application {

    private Stage primaryStage;
    private Stage splashStage;

    @Override
    public void init() throws Exception {
        super.init();
        
        // Initialize logger
        Logger.getInstance().info("Application", "Initializing VaultScope Enterprise");
        
        // Initialize database
        DatabaseManager.getInstance();
        
        // Log application startup
        DatabaseManager.getInstance().logAuditEvent("APPLICATION_START", "USER_ACTION", null, 
            "VaultScope application started");
    }

    @Override
    public void start(Stage stage) throws Exception {
        this.primaryStage = stage;
        showSplashScreen();
    }
    
    private void showSplashScreen() {
        try {
            FXMLLoader splashLoader = new FXMLLoader(getClass().getResource("/fxml/splash-screen.fxml"));
            Scene splashScene = new Scene(splashLoader.load(), 600, 400);
            
            // Apply theme to splash screen
            ThemeManager.applyTheme(splashScene);
            
            splashStage = new Stage();
            splashStage.setScene(splashScene);
            splashStage.initStyle(StageStyle.UNDECORATED);
            splashStage.setResizable(false);
            splashStage.setTitle("VaultScope - Loading");
            splashStage.centerOnScreen();
            
            // Set up splash screen controller
            SplashScreenController controller = splashLoader.getController();
            controller.setOnLoadComplete(() -> {
                splashStage.close();
                showMainApplication();
            });
            
            splashStage.show();
            
        } catch (Exception e) {
            Logger.getInstance().error("Application", "Failed to show splash screen", e.getMessage());
            // Fallback to main application
            showMainApplication();
        }
    }
    
    private void showMainApplication() {
        try {
            FXMLLoader fxmlLoader = new FXMLLoader(getClass().getResource("/fxml/main-view.fxml"));
            Scene scene = new Scene(fxmlLoader.load(), 1400, 900);
            
            // Apply theme
            ThemeManager.applyTheme(scene);
            
            primaryStage.setTitle("VaultScope - Enterprise API Security Assessment Tool");
            primaryStage.setScene(scene);
            primaryStage.setMinWidth(1200);
            primaryStage.setMinHeight(800);
            
            // Set application icon
            try {
                primaryStage.getIcons().add(new Image(getClass().getResourceAsStream("/images/vaultscope-icon.png")));
            } catch (Exception e) {
                Logger.getInstance().warning("Application", "Could not load application icon");
            }
            
            // Center the window
            primaryStage.centerOnScreen();
            
            // Show main application
            primaryStage.show();
            
            Logger.getInstance().info("Application", "VaultScope main application started successfully");
            
        } catch (Exception e) {
            Logger.getInstance().critical("Application", "Failed to start main application", e.getMessage());
            Platform.exit();
        }
    }
    
    @Override
    public void stop() throws Exception {
        super.stop();
        
        // Log application shutdown
        DatabaseManager.getInstance().logAuditEvent("APPLICATION_STOP", "USER_ACTION", null, 
            "VaultScope application stopped");
        
        // Close database connection
        DatabaseManager.getInstance().close();
        
        Logger.getInstance().info("Application", "VaultScope application stopped");
    }

    public static void main(String[] args) {
        // Set system properties for better performance
        System.setProperty("javafx.preloader", "");
        System.setProperty("prism.lcdtext", "false");
        System.setProperty("prism.text", "t2k");
        
        launch(args);
    }
}