package dev.cptcr.vaultscope.ui.components;

import javafx.animation.FadeTransition;
import javafx.animation.TranslateTransition;
import javafx.application.Platform;
import javafx.geometry.Pos;
import javafx.scene.control.Label;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javafx.util.Duration;

import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Modern notification system with toast-style messages
 */
public class NotificationManager {
    
    private static NotificationManager instance;
    private Stage primaryStage;
    private VBox notificationContainer;
    private final Queue<NotificationItem> notificationQueue = new ConcurrentLinkedQueue<>();
    private boolean isProcessing = false;
    
    public enum NotificationType {
        SUCCESS("notification-success", "✅"),
        INFO("notification-info", "ℹ️"),
        WARNING("notification-warning", "⚠️"),
        ERROR("notification-error", "❌"),
        SECURITY("notification-security", "🛡️");
        
        private final String styleClass;
        private final String icon;
        
        NotificationType(String styleClass, String icon) {
            this.styleClass = styleClass;
            this.icon = icon;
        }
        
        public String getStyleClass() {
            return styleClass;
        }
        
        public String getIcon() {
            return icon;
        }
    }
    
    private static class NotificationItem {
        final NotificationType type;
        final String title;
        final String message;
        final int duration;
        
        NotificationItem(NotificationType type, String title, String message, int duration) {
            this.type = type;
            this.title = title;
            this.message = message;
            this.duration = duration;
        }
    }
    
    private NotificationManager() {
        // Private constructor for singleton
    }
    
    public static NotificationManager getInstance() {
        if (instance == null) {
            instance = new NotificationManager();
        }
        return instance;
    }
    
    /**
     * Initialize the notification manager with the primary stage
     */
    public void initialize(Stage primaryStage) {
        this.primaryStage = primaryStage;
        createNotificationContainer();
    }
    
    private void createNotificationContainer() {
        notificationContainer = new VBox(10);
        notificationContainer.setAlignment(Pos.TOP_RIGHT);
        notificationContainer.setMaxWidth(400);
        notificationContainer.setMouseTransparent(true);
        
        // Position container in top-right corner
        StackPane.setAlignment(notificationContainer, Pos.TOP_RIGHT);
    }
    
    /**
     * Show a success notification
     */
    public void showSuccess(String title, String message) {
        showNotification(NotificationType.SUCCESS, title, message, 3000);
    }
    
    /**
     * Show an info notification
     */
    public void showInfo(String title, String message) {
        showNotification(NotificationType.INFO, title, message, 4000);
    }
    
    /**
     * Show a warning notification
     */
    public void showWarning(String title, String message) {
        showNotification(NotificationType.WARNING, title, message, 5000);
    }
    
    /**
     * Show an error notification
     */
    public void showError(String title, String message) {
        showNotification(NotificationType.ERROR, title, message, 6000);
    }
    
    /**
     * Show a security notification
     */
    public void showSecurity(String title, String message) {
        showNotification(NotificationType.SECURITY, title, message, 7000);
    }
    
    /**
     * Show a notification with custom duration
     */
    public void showNotification(NotificationType type, String title, String message, int durationMs) {
        NotificationItem item = new NotificationItem(type, title, message, durationMs);
        notificationQueue.offer(item);
        
        if (!isProcessing) {
            Platform.runLater(this::processNotificationQueue);
        }
    }
    
    private void processNotificationQueue() {
        if (isProcessing || notificationQueue.isEmpty()) {
            return;
        }
        
        isProcessing = true;
        NotificationItem item = notificationQueue.poll();
        
        if (item != null) {
            createAndShowNotification(item);
        }
    }
    
    private void createAndShowNotification(NotificationItem item) {
        // Create notification content
        VBox notificationContent = new VBox(5);
        notificationContent.getStyleClass().addAll("notification", item.type.getStyleClass());
        notificationContent.setMaxWidth(350);
        notificationContent.setMinHeight(60);
        
        // Create title
        Label titleLabel = new Label(item.type.getIcon() + " " + item.title);
        titleLabel.getStyleClass().add("notification-title");
        
        // Create message
        Label messageLabel = new Label(item.message);
        messageLabel.getStyleClass().add("notification-message");
        messageLabel.setWrapText(true);
        
        notificationContent.getChildren().addAll(titleLabel, messageLabel);
        
        // Add to container
        notificationContainer.getChildren().add(notificationContent);
        
        // Slide in animation
        TranslateTransition slideIn = new TranslateTransition(Duration.millis(300), notificationContent);
        slideIn.setFromX(400);
        slideIn.setToX(0);
        
        FadeTransition fadeIn = new FadeTransition(Duration.millis(300), notificationContent);
        fadeIn.setFromValue(0.0);
        fadeIn.setToValue(1.0);
        
        slideIn.play();
        fadeIn.play();
        
        // Auto-dismiss after duration
        Platform.runLater(() -> {
            new Thread(() -> {
                try {
                    Thread.sleep(item.duration);
                    Platform.runLater(() -> dismissNotification(notificationContent));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }).start();
        });
        
        // Set up click to dismiss
        notificationContent.setOnMouseClicked(e -> dismissNotification(notificationContent));
        
        // Continue processing queue
        isProcessing = false;
        if (!notificationQueue.isEmpty()) {
            Platform.runLater(this::processNotificationQueue);
        }
    }
    
    private void dismissNotification(VBox notification) {
        // Slide out animation
        TranslateTransition slideOut = new TranslateTransition(Duration.millis(200), notification);
        slideOut.setFromX(0);
        slideOut.setToX(400);
        
        FadeTransition fadeOut = new FadeTransition(Duration.millis(200), notification);
        fadeOut.setFromValue(1.0);
        fadeOut.setToValue(0.0);
        
        slideOut.setOnFinished(e -> {
            notificationContainer.getChildren().remove(notification);
            
            // Process next notification in queue
            if (!notificationQueue.isEmpty()) {
                processNotificationQueue();
            }
        });
        
        slideOut.play();
        fadeOut.play();
    }
    
    /**
     * Clear all notifications
     */
    public void clearAll() {
        notificationQueue.clear();
        notificationContainer.getChildren().clear();
        isProcessing = false;
    }
    
    /**
     * Get the notification container to add to scene
     */
    public VBox getNotificationContainer() {
        return notificationContainer;
    }
}