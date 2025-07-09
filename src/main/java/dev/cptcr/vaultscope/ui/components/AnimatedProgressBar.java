package dev.cptcr.vaultscope.ui.components;

import javafx.animation.KeyFrame;
import javafx.animation.Timeline;
import javafx.scene.control.ProgressBar;
import javafx.scene.effect.DropShadow;
import javafx.scene.paint.Color;
import javafx.util.Duration;

/**
 * Animated progress bar with smooth transitions and visual effects
 */
public class AnimatedProgressBar extends ProgressBar {
    
    private final Timeline animation;
    private final DropShadow glowEffect;
    private double targetProgress = 0.0;
    private double animationSpeed = 0.02;
    
    public AnimatedProgressBar() {
        super();
        initialize();
    }
    
    public AnimatedProgressBar(double progress) {
        super(progress);
        initialize();
    }
    
    private void initialize() {
        // Initialize glow effect
        glowEffect = new DropShadow();
        glowEffect.setColor(Color.rgb(124, 77, 255, 0.6));
        glowEffect.setRadius(10);
        glowEffect.setSpread(0.3);
        setEffect(glowEffect);
        
        // Initialize animation
        animation = new Timeline(
            new KeyFrame(Duration.millis(16), e -> updateProgress())
        );
        animation.setCycleCount(Timeline.INDEFINITE);
        
        // Apply styling
        getStyleClass().add("animated-progress-bar");
        
        // Start animation
        animation.play();
    }
    
    private void updateProgress() {
        double currentProgress = getProgress();
        
        if (Math.abs(currentProgress - targetProgress) > 0.001) {
            double diff = targetProgress - currentProgress;
            double step = diff * animationSpeed;
            
            // Ensure minimum step size
            if (Math.abs(step) < 0.001) {
                step = Math.signum(diff) * 0.001;
            }
            
            double newProgress = currentProgress + step;
            
            // Clamp to target if very close
            if (Math.abs(newProgress - targetProgress) < 0.001) {
                newProgress = targetProgress;
            }
            
            setProgress(newProgress);
            
            // Update glow effect based on progress
            updateGlowEffect(newProgress);
        }
    }
    
    private void updateGlowEffect(double progress) {
        if (progress >= 0 && progress <= 1) {
            // Change glow color based on progress
            Color glowColor;
            if (progress < 0.3) {
                glowColor = Color.rgb(255, 64, 64, 0.6); // Red for low progress
            } else if (progress < 0.7) {
                glowColor = Color.rgb(255, 165, 0, 0.6); // Orange for medium progress
            } else {
                glowColor = Color.rgb(76, 175, 80, 0.6); // Green for high progress
            }
            
            glowEffect.setColor(glowColor);
            glowEffect.setRadius(8 + (progress * 4)); // Increase glow with progress
        }
    }
    
    /**
     * Set progress with smooth animation
     */
    public void setAnimatedProgress(double progress) {
        this.targetProgress = Math.max(0, Math.min(1, progress));
    }
    
    /**
     * Set animation speed (0.01 = slow, 0.1 = fast)
     */
    public void setAnimationSpeed(double speed) {
        this.animationSpeed = Math.max(0.001, Math.min(0.2, speed));
    }
    
    /**
     * Instantly set progress without animation
     */
    public void setInstantProgress(double progress) {
        this.targetProgress = Math.max(0, Math.min(1, progress));
        setProgress(targetProgress);
        updateGlowEffect(targetProgress);
    }
    
    /**
     * Add pulsing effect for indeterminate progress
     */
    public void setPulsing(boolean pulsing) {
        if (pulsing) {
            setProgress(ProgressBar.INDETERMINATE_PROGRESS);
            getStyleClass().add("pulsing-progress");
        } else {
            getStyleClass().remove("pulsing-progress");
        }
    }
    
    /**
     * Stop all animations
     */
    public void stopAnimation() {
        animation.stop();
    }
    
    /**
     * Resume animations
     */
    public void resumeAnimation() {
        animation.play();
    }
}