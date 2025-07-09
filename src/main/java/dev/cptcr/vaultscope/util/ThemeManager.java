package dev.cptcr.vaultscope.util;

import javafx.scene.Scene;
import java.util.prefs.Preferences;

public class ThemeManager {
    
    public enum Theme {
        DARK_PURPLE("Dark Purple", "/css/dark-purple-theme.css"),
        LIGHT_PURPLE("Light Purple", "/css/light-purple-theme.css"),
        ENTERPRISE_DARK("Enterprise Dark", "/css/enterprise-dark-theme.css");
        
        private final String displayName;
        private final String cssPath;
        
        Theme(String displayName, String cssPath) {
            this.displayName = displayName;
            this.cssPath = cssPath;
        }
        
        public String getDisplayName() {
            return displayName;
        }
        
        public String getCssPath() {
            return cssPath;
        }
    }
    
    private static final String THEME_PREFERENCE_KEY = "selected_theme";
    private static final Preferences preferences = Preferences.userNodeForPackage(ThemeManager.class);
    private static Theme currentTheme;
    private static ThemeManager instance;
    
    static {
        String themeName = preferences.get(THEME_PREFERENCE_KEY, Theme.DARK_PURPLE.name());
        try {
            currentTheme = Theme.valueOf(themeName);
        } catch (IllegalArgumentException e) {
            currentTheme = Theme.DARK_PURPLE;
        }
        instance = new ThemeManager();
    }
    
    public static ThemeManager getInstance() {
        return instance;
    }
    
    public static Theme getCurrentTheme() {
        return currentTheme;
    }
    
    public static void setTheme(Theme theme) {
        currentTheme = theme;
        preferences.put(THEME_PREFERENCE_KEY, theme.name());
    }
    
    public static void applyTheme(Scene scene) {
        scene.getStylesheets().clear();
        scene.getStylesheets().add(ThemeManager.class.getResource("/css/base-styles.css").toExternalForm());
        scene.getStylesheets().add(ThemeManager.class.getResource(currentTheme.getCssPath()).toExternalForm());
    }
    
    public static Theme getNextTheme() {
        Theme[] themes = Theme.values();
        int currentIndex = java.util.Arrays.asList(themes).indexOf(currentTheme);
        return themes[(currentIndex + 1) % themes.length];
    }
}