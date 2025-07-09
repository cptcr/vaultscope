package dev.cptcr.vaultscope.core;

import dev.cptcr.vaultscope.security.SecurityManager;
import dev.cptcr.vaultscope.service.AuthenticationTester;
import dev.cptcr.vaultscope.service.ReportService;
import dev.cptcr.vaultscope.service.SecurityScanner;
import dev.cptcr.vaultscope.ui.components.NotificationManager;
import dev.cptcr.vaultscope.util.DatabaseManager;
import dev.cptcr.vaultscope.util.Logger;
import dev.cptcr.vaultscope.util.ThemeManager;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Central application context for dependency injection and lifecycle management
 * Implements singleton pattern with lazy initialization
 */
public class ApplicationContext {
    
    private static volatile ApplicationContext instance;
    private static final Object lock = new Object();
    
    // Core services
    private volatile SecurityManager securityManager;
    private volatile DatabaseManager databaseManager;
    private volatile Logger logger;
    private volatile ThemeManager themeManager;
    private volatile NotificationManager notificationManager;
    
    // Business services
    private volatile SecurityScanner securityScanner;
    private volatile AuthenticationTester authenticationTester;
    private volatile ReportService reportService;
    
    // System resources
    private volatile ExecutorService executorService;
    private volatile ExecutorService backgroundExecutorService;
    
    // Lifecycle management
    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final AtomicBoolean shutdown = new AtomicBoolean(false);
    
    /**
     * Private constructor to prevent direct instantiation
     */
    private ApplicationContext() {
        // Private constructor
    }
    
    /**
     * Get the singleton instance of ApplicationContext
     * Thread-safe double-checked locking pattern
     */
    public static ApplicationContext getInstance() {
        if (instance == null) {
            synchronized (lock) {
                if (instance == null) {
                    instance = new ApplicationContext();
                }
            }
        }
        return instance;
    }
    
    /**
     * Initialize the application context
     * This method is thread-safe and idempotent
     */
    public CompletableFuture<Void> initialize() {
        if (initialized.get()) {
            return CompletableFuture.completedFuture(null);
        }
        
        return CompletableFuture.runAsync(() -> {
            synchronized (lock) {
                if (initialized.get()) {
                    return;
                }
                
                try {
                    // Initialize core infrastructure
                    initializeInfrastructure();
                    
                    // Initialize business services
                    initializeServices();
                    
                    // Mark as initialized
                    initialized.set(true);
                    
                    getLogger().info("ApplicationContext", "Application context initialized successfully");
                    
                } catch (Exception e) {
                    getLogger().error("ApplicationContext", "Failed to initialize application context", e.getMessage());
                    throw new RuntimeException("Application context initialization failed", e);
                }
            }
        });
    }
    
    /**
     * Initialize core infrastructure components
     */
    private void initializeInfrastructure() {
        // Initialize logger first
        logger = Logger.getInstance();
        
        // Initialize thread pools
        executorService = Executors.newFixedThreadPool(4, r -> {
            Thread t = new Thread(r, "VaultScope-Worker");
            t.setDaemon(false);
            return t;
        });
        
        backgroundExecutorService = Executors.newFixedThreadPool(2, r -> {
            Thread t = new Thread(r, "VaultScope-Background");
            t.setDaemon(true);
            return t;
        });
        
        // Initialize security manager
        securityManager = new SecurityManager();
        
        // Initialize database manager
        databaseManager = DatabaseManager.getInstance();
        
        // Initialize theme manager
        themeManager = ThemeManager.getInstance();
        
        // Initialize notification manager
        notificationManager = NotificationManager.getInstance();
        
        logger.info("ApplicationContext", "Infrastructure components initialized");
    }
    
    /**
     * Initialize business services
     */
    private void initializeServices() {
        // Initialize security scanner
        securityScanner = new SecurityScanner();
        
        // Initialize authentication tester
        authenticationTester = new AuthenticationTester();
        
        // Initialize report service
        reportService = new ReportService();
        
        logger.info("ApplicationContext", "Business services initialized");
    }
    
    /**
     * Shutdown the application context gracefully
     */
    public CompletableFuture<Void> shutdown() {
        if (shutdown.get()) {
            return CompletableFuture.completedFuture(null);
        }
        
        return CompletableFuture.runAsync(() -> {
            synchronized (lock) {
                if (shutdown.get()) {
                    return;
                }
                
                try {
                    logger.info("ApplicationContext", "Starting application shutdown...");
                    
                    // Shutdown services in reverse order
                    shutdownServices();
                    
                    // Shutdown infrastructure
                    shutdownInfrastructure();
                    
                    // Mark as shutdown
                    shutdown.set(true);
                    
                    logger.info("ApplicationContext", "Application shutdown completed");
                    
                } catch (Exception e) {
                    logger.error("ApplicationContext", "Error during shutdown", e.getMessage());
                }
            }
        });
    }
    
    /**
     * Shutdown business services
     */
    private void shutdownServices() {
        // Services don't typically need explicit shutdown
        // But we can clean up resources if needed
        
        if (reportService != null) {
            // reportService.cleanup();
        }
        
        if (authenticationTester != null) {
            // authenticationTester.cleanup();
        }
        
        if (securityScanner != null) {
            // securityScanner.cleanup();
        }
        
        logger.info("ApplicationContext", "Business services shutdown");
    }
    
    /**
     * Shutdown infrastructure components
     */
    private void shutdownInfrastructure() {
        // Shutdown thread pools
        if (executorService != null && !executorService.isShutdown()) {
            executorService.shutdown();
        }
        
        if (backgroundExecutorService != null && !backgroundExecutorService.isShutdown()) {
            backgroundExecutorService.shutdown();
        }
        
        // Shutdown database
        if (databaseManager != null) {
            databaseManager.close();
        }
        
        // Clear notification manager
        if (notificationManager != null) {
            notificationManager.clearAll();
        }
        
        logger.info("ApplicationContext", "Infrastructure shutdown");
    }
    
    /**
     * Get the security manager instance
     */
    public SecurityManager getSecurityManager() {
        ensureInitialized();
        return securityManager;
    }
    
    /**
     * Get the database manager instance
     */
    public DatabaseManager getDatabaseManager() {
        ensureInitialized();
        return databaseManager;
    }
    
    /**
     * Get the logger instance
     */
    public Logger getLogger() {
        // Logger is available even before full initialization
        if (logger == null) {
            logger = Logger.getInstance();
        }
        return logger;
    }
    
    /**
     * Get the theme manager instance
     */
    public ThemeManager getThemeManager() {
        ensureInitialized();
        return themeManager;
    }
    
    /**
     * Get the notification manager instance
     */
    public NotificationManager getNotificationManager() {
        ensureInitialized();
        return notificationManager;
    }
    
    /**
     * Get the security scanner instance
     */
    public SecurityScanner getSecurityScanner() {
        ensureInitialized();
        return securityScanner;
    }
    
    /**
     * Get the authentication tester instance
     */
    public AuthenticationTester getAuthenticationTester() {
        ensureInitialized();
        return authenticationTester;
    }
    
    /**
     * Get the report service instance
     */
    public ReportService getReportService() {
        ensureInitialized();
        return reportService;
    }
    
    /**
     * Get the main executor service
     */
    public ExecutorService getExecutorService() {
        ensureInitialized();
        return executorService;
    }
    
    /**
     * Get the background executor service
     */
    public ExecutorService getBackgroundExecutorService() {
        ensureInitialized();
        return backgroundExecutorService;
    }
    
    /**
     * Check if the application context is initialized
     */
    public boolean isInitialized() {
        return initialized.get();
    }
    
    /**
     * Check if the application context is shutdown
     */
    public boolean isShutdown() {
        return shutdown.get();
    }
    
    /**
     * Ensure the application context is initialized
     */
    private void ensureInitialized() {
        if (!initialized.get()) {
            throw new IllegalStateException("ApplicationContext is not initialized. Call initialize() first.");
        }
        
        if (shutdown.get()) {
            throw new IllegalStateException("ApplicationContext has been shutdown.");
        }
    }
    
    /**
     * Reset the application context (for testing purposes)
     */
    public static void reset() {
        synchronized (lock) {
            if (instance != null) {
                instance.shutdown().join();
                instance = null;
            }
        }
    }
}