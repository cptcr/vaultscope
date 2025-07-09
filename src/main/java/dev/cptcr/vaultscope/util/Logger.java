package dev.cptcr.vaultscope.util;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class Logger {
    
    public enum Level {
        DEBUG("DEBUG", "🔍"),
        INFO("INFO", "ℹ️"),
        WARNING("WARN", "⚠️"),
        ERROR("ERROR", "❌"),
        CRITICAL("CRIT", "🚨"),
        SECURITY("SEC", "🛡️");
        
        private final String name;
        private final String emoji;
        
        Level(String name, String emoji) {
            this.name = name;
            this.emoji = emoji;
        }
        
        public String getName() { return name; }
        public String getEmoji() { return emoji; }
    }
    
    public static class LogEntry {
        private final LocalDateTime timestamp;
        private final Level level;
        private final String category;
        private final String message;
        private final String details;
        
        public LogEntry(LocalDateTime timestamp, Level level, String category, String message, String details) {
            this.timestamp = timestamp;
            this.level = level;
            this.category = category;
            this.message = message;
            this.details = details;
        }
        
        public LocalDateTime getTimestamp() { return timestamp; }
        public Level getLevel() { return level; }
        public String getCategory() { return category; }
        public String getMessage() { return message; }
        public String getDetails() { return details; }
        
        @Override
        public String toString() {
            return String.format("[%s] %s %s [%s] %s%s",
                timestamp.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")),
                level.getEmoji(),
                level.getName(),
                category,
                message,
                details != null ? "\n" + details : ""
            );
        }
    }
    
    private static final Logger INSTANCE = new Logger();
    private final List<LogEntry> entries = new CopyOnWriteArrayList<>();
    private final List<LogListener> listeners = new CopyOnWriteArrayList<>();
    private Level minimumLevel = Level.INFO;
    
    public interface LogListener {
        void onLogEntry(LogEntry entry);
    }
    
    private Logger() {}
    
    public static Logger getInstance() {
        return INSTANCE;
    }
    
    public void setMinimumLevel(Level level) {
        this.minimumLevel = level;
    }
    
    public void addListener(LogListener listener) {
        listeners.add(listener);
    }
    
    public void removeListener(LogListener listener) {
        listeners.remove(listener);
    }
    
    public void log(Level level, String category, String message, String details) {
        if (level.ordinal() < minimumLevel.ordinal()) {
            return;
        }
        
        LogEntry entry = new LogEntry(LocalDateTime.now(), level, category, message, details);
        entries.add(entry);
        
        // Limit log size to prevent memory issues
        if (entries.size() > 10000) {
            entries.remove(0);
        }
        
        // Notify listeners
        for (LogListener listener : listeners) {
            try {
                listener.onLogEntry(entry);
            } catch (Exception e) {
                // Ignore listener errors to prevent cascading failures
            }
        }
    }
    
    public void log(Level level, String category, String message) {
        log(level, category, message, null);
    }
    
    public void debug(String category, String message, String details) {
        log(Level.DEBUG, category, message, details);
    }
    
    public void debug(String category, String message) {
        log(Level.DEBUG, category, message, null);
    }
    
    public void info(String category, String message, String details) {
        log(Level.INFO, category, message, details);
    }
    
    public void info(String category, String message) {
        log(Level.INFO, category, message, null);
    }
    
    public void warning(String category, String message, String details) {
        log(Level.WARNING, category, message, details);
    }
    
    public void warning(String category, String message) {
        log(Level.WARNING, category, message, null);
    }
    
    public void error(String category, String message, String details) {
        log(Level.ERROR, category, message, details);
    }
    
    public void error(String category, String message) {
        log(Level.ERROR, category, message, null);
    }
    
    public void critical(String category, String message, String details) {
        log(Level.CRITICAL, category, message, details);
    }
    
    public void critical(String category, String message) {
        log(Level.CRITICAL, category, message, null);
    }
    
    public void security(String category, String message, String details) {
        log(Level.SECURITY, category, message, details);
    }
    
    public void security(String category, String message) {
        log(Level.SECURITY, category, message, null);
    }
    
    public List<LogEntry> getEntries() {
        return new ArrayList<>(entries);
    }
    
    public List<LogEntry> getEntriesForCategory(String category) {
        return entries.stream()
            .filter(entry -> entry.getCategory().equals(category))
            .collect(ArrayList::new, ArrayList::add, ArrayList::addAll);
    }
    
    public List<LogEntry> getEntriesForLevel(Level level) {
        return entries.stream()
            .filter(entry -> entry.getLevel() == level)
            .collect(ArrayList::new, ArrayList::add, ArrayList::addAll);
    }
    
    public void clear() {
        entries.clear();
    }
    
    public void exportToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("VaultScope Security Assessment Log\n");
        sb.append("Generated: ").append(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))).append("\n");
        sb.append("=" .repeat(80)).append("\n\n");
        
        for (LogEntry entry : entries) {
            sb.append(entry.toString()).append("\n");
        }
        
        // This would typically be saved to a file or exported
        System.out.println(sb.toString());
    }
}