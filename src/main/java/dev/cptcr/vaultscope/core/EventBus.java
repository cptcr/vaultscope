package dev.cptcr.vaultscope.core;

import dev.cptcr.vaultscope.util.Logger;

import java.lang.reflect.Method;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;

/**
 * Simple event bus implementation for decoupled communication between components
 * Thread-safe and supports both synchronous and asynchronous event handling
 */
public class EventBus {
    
    private static volatile EventBus instance;
    private static final Object lock = new Object();
    
    private final ConcurrentHashMap<Class<?>, List<EventHandler>> handlers = new ConcurrentHashMap<>();
    private final ExecutorService executorService;
    private final Logger logger;
    
    /**
     * Event handler interface
     */
    @FunctionalInterface
    public interface EventHandler {
        void handle(Object event);
    }
    
    /**
     * Event handler with method information
     */
    private static class MethodEventHandler implements EventHandler {
        private final Object target;
        private final Method method;
        
        public MethodEventHandler(Object target, Method method) {
            this.target = target;
            this.method = method;
        }
        
        @Override
        public void handle(Object event) {
            try {
                method.invoke(target, event);
            } catch (Exception e) {
                Logger.getInstance().error("EventBus", 
                    "Failed to handle event: " + event.getClass().getSimpleName(), 
                    e.getMessage());
            }
        }
    }
    
    /**
     * Private constructor
     */
    private EventBus() {
        this.executorService = ApplicationContext.getInstance().getExecutorService();
        this.logger = ApplicationContext.getInstance().getLogger();
    }
    
    /**
     * Get the singleton instance
     */
    public static EventBus getInstance() {
        if (instance == null) {
            synchronized (lock) {
                if (instance == null) {
                    instance = new EventBus();
                }
            }
        }
        return instance;
    }
    
    /**
     * Subscribe to events of a specific type
     */
    public <T> void subscribe(Class<T> eventType, EventHandler handler) {
        handlers.computeIfAbsent(eventType, k -> new CopyOnWriteArrayList<>()).add(handler);
        logger.debug("EventBus", "Subscribed to event type: " + eventType.getSimpleName());
    }
    
    /**
     * Subscribe an object with @EventHandler annotated methods
     */
    public void subscribe(Object subscriber) {
        Class<?> clazz = subscriber.getClass();
        
        for (Method method : clazz.getDeclaredMethods()) {
            if (method.isAnnotationPresent(EventHandler.class)) {
                Class<?>[] paramTypes = method.getParameterTypes();
                
                if (paramTypes.length == 1) {
                    Class<?> eventType = paramTypes[0];
                    method.setAccessible(true);
                    
                    subscribe(eventType, new MethodEventHandler(subscriber, method));
                    logger.debug("EventBus", "Subscribed method " + method.getName() + 
                        " to event type: " + eventType.getSimpleName());
                }
            }
        }
    }
    
    /**
     * Unsubscribe from events
     */
    public void unsubscribe(Object subscriber) {
        handlers.values().forEach(handlerList -> 
            handlerList.removeIf(handler -> 
                handler instanceof MethodEventHandler && 
                ((MethodEventHandler) handler).target == subscriber));
        
        logger.debug("EventBus", "Unsubscribed: " + subscriber.getClass().getSimpleName());
    }
    
    /**
     * Publish an event synchronously
     */
    public void publish(Object event) {
        Class<?> eventType = event.getClass();
        List<EventHandler> eventHandlers = handlers.get(eventType);
        
        if (eventHandlers != null) {
            logger.debug("EventBus", "Publishing event: " + eventType.getSimpleName() + 
                " to " + eventHandlers.size() + " handlers");
            
            for (EventHandler handler : eventHandlers) {
                try {
                    handler.handle(event);
                } catch (Exception e) {
                    logger.error("EventBus", "Error handling event: " + eventType.getSimpleName(), 
                        e.getMessage());
                }
            }
        }
    }
    
    /**
     * Publish an event asynchronously
     */
    public void publishAsync(Object event) {
        executorService.submit(() -> publish(event));
    }
    
    /**
     * Clear all event handlers
     */
    public void clear() {
        handlers.clear();
        logger.debug("EventBus", "Cleared all event handlers");
    }
    
    /**
     * Get the number of handlers for a specific event type
     */
    public int getHandlerCount(Class<?> eventType) {
        List<EventHandler> eventHandlers = handlers.get(eventType);
        return eventHandlers != null ? eventHandlers.size() : 0;
    }
    
    /**
     * Event handler annotation
     */
    @java.lang.annotation.Target(java.lang.annotation.ElementType.METHOD)
    @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
    public @interface EventHandler {
    }
    
    // Common event types
    
    /**
     * Security scan started event
     */
    public static class SecurityScanStartedEvent {
        private final String targetUrl;
        private final String authType;
        
        public SecurityScanStartedEvent(String targetUrl, String authType) {
            this.targetUrl = targetUrl;
            this.authType = authType;
        }
        
        public String getTargetUrl() { return targetUrl; }
        public String getAuthType() { return authType; }
    }
    
    /**
     * Security scan completed event
     */
    public static class SecurityScanCompletedEvent {
        private final String targetUrl;
        private final int vulnerabilityCount;
        private final int securityScore;
        
        public SecurityScanCompletedEvent(String targetUrl, int vulnerabilityCount, int securityScore) {
            this.targetUrl = targetUrl;
            this.vulnerabilityCount = vulnerabilityCount;
            this.securityScore = securityScore;
        }
        
        public String getTargetUrl() { return targetUrl; }
        public int getVulnerabilityCount() { return vulnerabilityCount; }
        public int getSecurityScore() { return securityScore; }
    }
    
    /**
     * Security scan failed event
     */
    public static class SecurityScanFailedEvent {
        private final String targetUrl;
        private final String errorMessage;
        
        public SecurityScanFailedEvent(String targetUrl, String errorMessage) {
            this.targetUrl = targetUrl;
            this.errorMessage = errorMessage;
        }
        
        public String getTargetUrl() { return targetUrl; }
        public String getErrorMessage() { return errorMessage; }
    }
    
    /**
     * Theme changed event
     */
    public static class ThemeChangedEvent {
        private final String oldTheme;
        private final String newTheme;
        
        public ThemeChangedEvent(String oldTheme, String newTheme) {
            this.oldTheme = oldTheme;
            this.newTheme = newTheme;
        }
        
        public String getOldTheme() { return oldTheme; }
        public String getNewTheme() { return newTheme; }
    }
    
    /**
     * Application startup event
     */
    public static class ApplicationStartupEvent {
        private final long startupTime;
        
        public ApplicationStartupEvent(long startupTime) {
            this.startupTime = startupTime;
        }
        
        public long getStartupTime() { return startupTime; }
    }
    
    /**
     * Application shutdown event
     */
    public static class ApplicationShutdownEvent {
        private final long shutdownTime;
        
        public ApplicationShutdownEvent(long shutdownTime) {
            this.shutdownTime = shutdownTime;
        }
        
        public long getShutdownTime() { return shutdownTime; }
    }
}