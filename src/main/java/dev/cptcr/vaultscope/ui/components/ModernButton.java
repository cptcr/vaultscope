package dev.cptcr.vaultscope.ui.components;

import javafx.animation.FadeTransition;
import javafx.animation.ScaleTransition;
import javafx.animation.TranslateTransition;
import javafx.scene.control.Button;
import javafx.scene.effect.DropShadow;
import javafx.scene.paint.Color;
import javafx.util.Duration;

/**
 * Modern button component with animations and enhanced styling
 */
public class ModernButton extends Button {
    
    private DropShadow dropShadow;
    private ScaleTransition scaleTransition;
    private FadeTransition fadeTransition;
    
    public ModernButton() {
        super();
        initialize();
    }
    
    public ModernButton(String text) {
        super(text);
        initialize();
    }
    
    private void initialize() {
        // Initialize drop shadow effect
        dropShadow = new DropShadow();
        dropShadow.setColor(Color.rgb(0, 0, 0, 0.3));
        dropShadow.setRadius(8);
        dropShadow.setOffsetX(0);
        dropShadow.setOffsetY(2);
        
        // Initialize animations
        scaleTransition = new ScaleTransition(Duration.millis(100), this);
        fadeTransition = new FadeTransition(Duration.millis(150), this);
        
        // Set up hover effects
        setupHoverEffects();
        
        // Set up click effects
        setupClickEffects();
        
        // Apply default styling
        getStyleClass().add("modern-button");
        setEffect(dropShadow);
    }
    
    private void setupHoverEffects() {
        setOnMouseEntered(e -> {
            // Scale up slightly on hover
            scaleTransition.setToX(1.02);
            scaleTransition.setToY(1.02);
            scaleTransition.play();
            
            // Enhance drop shadow
            dropShadow.setRadius(10);
            dropShadow.setOffsetY(3);
        });
        
        setOnMouseExited(e -> {
            // Scale back to normal
            scaleTransition.setToX(1.0);
            scaleTransition.setToY(1.0);
            scaleTransition.play();
            
            // Reset drop shadow
            dropShadow.setRadius(8);
            dropShadow.setOffsetY(2);
        });
    }
    
    private void setupClickEffects() {
        setOnMousePressed(e -> {
            // Scale down on press
            scaleTransition.setToX(0.95);
            scaleTransition.setToY(0.95);
            scaleTransition.play();
            
            // Reduce drop shadow
            dropShadow.setRadius(4);
            dropShadow.setOffsetY(1);
        });
        
        setOnMouseReleased(e -> {
            // Scale back up on release
            scaleTransition.setToX(1.02);
            scaleTransition.setToY(1.02);
            scaleTransition.play();
            
            // Restore drop shadow
            dropShadow.setRadius(10);
            dropShadow.setOffsetY(3);
        });
    }
    
    /**
     * Add a subtle pulse animation
     */
    public void addPulseAnimation() {
        FadeTransition pulse = new FadeTransition(Duration.millis(1000), this);
        pulse.setFromValue(1.0);
        pulse.setToValue(0.7);
        pulse.setAutoReverse(true);
        pulse.setCycleCount(FadeTransition.INDEFINITE);
        pulse.play();
    }
    
    /**
     * Add a shake animation for errors
     */
    public void addShakeAnimation() {
        TranslateTransition shake = new TranslateTransition(Duration.millis(50), this);
        shake.setFromX(0);
        shake.setToX(5);
        shake.setAutoReverse(true);
        shake.setCycleCount(6);
        shake.play();
    }
    
    /**
     * Set button as primary action
     */
    public void setPrimary() {
        getStyleClass().removeAll("secondary-button", "danger-button");
        getStyleClass().add("primary-button");
    }
    
    /**
     * Set button as secondary action
     */
    public void setSecondary() {
        getStyleClass().removeAll("primary-button", "danger-button");
        getStyleClass().add("secondary-button");
    }
    
    /**
     * Set button as danger action
     */
    public void setDanger() {
        getStyleClass().removeAll("primary-button", "secondary-button");
        getStyleClass().add("danger-button");
    }
}