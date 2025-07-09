package dev.cptcr.vaultscope.util;

import dev.cptcr.vaultscope.model.SecurityResult;
import dev.cptcr.vaultscope.model.Vulnerability;

import java.sql.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.prefs.Preferences;

public class DatabaseManager {
    
    private static final String DB_NAME = "vaultscope.db";
    private static final String DB_PATH = System.getProperty("user.home") + "/.vaultscope/" + DB_NAME;
    private static DatabaseManager instance;
    private Connection connection;
    
    private DatabaseManager() {
        initializeDatabase();
    }
    
    public static synchronized DatabaseManager getInstance() {
        if (instance == null) {
            instance = new DatabaseManager();
        }
        return instance;
    }
    
    private void initializeDatabase() {
        try {
            // Create directory if it doesn't exist
            java.nio.file.Files.createDirectories(java.nio.file.Paths.get(DB_PATH).getParent());
            
            // Connect to SQLite database
            connection = DriverManager.getConnection("jdbc:sqlite:" + DB_PATH);
            
            // Create tables
            createTables();
            
            Logger.getInstance().info("Database", "Database initialized successfully");
        } catch (Exception e) {
            Logger.getInstance().error("Database", "Failed to initialize database", e.getMessage());
        }
    }
    
    private void createTables() throws SQLException {
        String createScanSessionsTable = """
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                scan_timestamp DATETIME NOT NULL,
                auth_type TEXT,
                total_vulnerabilities INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                security_score INTEGER DEFAULT 0,
                scan_duration_ms INTEGER DEFAULT 0,
                status TEXT DEFAULT 'COMPLETED'
            )
        """;
        
        String createVulnerabilitiesTable = """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                description TEXT NOT NULL,
                cwe_id TEXT,
                cvss_score REAL,
                remediation TEXT,
                evidence TEXT,
                discovered_at DATETIME NOT NULL,
                FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
            )
        """;
        
        String createSettingsTable = """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at DATETIME NOT NULL
            )
        """;
        
        String createAuditLogTable = """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                user_action TEXT NOT NULL,
                target_url TEXT,
                timestamp DATETIME NOT NULL,
                details TEXT,
                ip_address TEXT,
                user_agent TEXT
            )
        """;
        
        connection.createStatement().execute(createScanSessionsTable);
        connection.createStatement().execute(createVulnerabilitiesTable);
        connection.createStatement().execute(createSettingsTable);
        connection.createStatement().execute(createAuditLogTable);
        
        // Create indexes for performance
        connection.createStatement().execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_session_id ON vulnerabilities(session_id)");
        connection.createStatement().execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity)");
        connection.createStatement().execute("CREATE INDEX IF NOT EXISTS idx_scan_sessions_timestamp ON scan_sessions(scan_timestamp)");
        connection.createStatement().execute("CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp)");
    }
    
    public long saveScanSession(String targetUrl, String authType, SecurityResult result) {
        String sql = """
            INSERT INTO scan_sessions (target_url, scan_timestamp, auth_type, total_vulnerabilities, 
                                     critical_count, high_count, medium_count, low_count, security_score, 
                                     scan_duration_ms, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """;
        
        try (PreparedStatement stmt = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            stmt.setString(1, targetUrl);
            stmt.setTimestamp(2, Timestamp.valueOf(LocalDateTime.now()));
            stmt.setString(3, authType);
            stmt.setInt(4, result.getVulnerabilities().size());
            stmt.setInt(5, countVulnerabilitiesBySeverity(result.getVulnerabilities(), "Critical"));
            stmt.setInt(6, countVulnerabilitiesBySeverity(result.getVulnerabilities(), "High"));
            stmt.setInt(7, countVulnerabilitiesBySeverity(result.getVulnerabilities(), "Medium"));
            stmt.setInt(8, countVulnerabilitiesBySeverity(result.getVulnerabilities(), "Low"));
            stmt.setInt(9, result.getSecurityScore());
            stmt.setLong(10, 0); // scan duration would be calculated
            stmt.setString(11, "COMPLETED");
            
            stmt.executeUpdate();
            
            ResultSet generatedKeys = stmt.getGeneratedKeys();
            if (generatedKeys.next()) {
                long sessionId = generatedKeys.getLong(1);
                
                // Save vulnerabilities
                saveVulnerabilities(sessionId, result.getVulnerabilities());
                
                Logger.getInstance().info("Database", "Scan session saved with ID: " + sessionId);
                return sessionId;
            }
        } catch (SQLException e) {
            Logger.getInstance().error("Database", "Failed to save scan session", e.getMessage());
        }
        return -1;
    }
    
    private void saveVulnerabilities(long sessionId, List<Vulnerability> vulnerabilities) {
        String sql = """
            INSERT INTO vulnerabilities (session_id, type, severity, endpoint, description, 
                                       cwe_id, cvss_score, remediation, evidence, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """;
        
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            for (Vulnerability vuln : vulnerabilities) {
                stmt.setLong(1, sessionId);
                stmt.setString(2, vuln.getType());
                stmt.setString(3, vuln.getSeverity());
                stmt.setString(4, vuln.getEndpoint());
                stmt.setString(5, vuln.getDescription());
                stmt.setString(6, vuln.getCweId());
                stmt.setDouble(7, vuln.getCvssScore());
                stmt.setString(8, vuln.getRemediation());
                stmt.setString(9, vuln.getEvidence());
                stmt.setTimestamp(10, Timestamp.valueOf(LocalDateTime.now()));
                stmt.addBatch();
            }
            stmt.executeBatch();
        } catch (SQLException e) {
            Logger.getInstance().error("Database", "Failed to save vulnerabilities", e.getMessage());
        }
    }
    
    public List<ScanSession> getScanHistory(int limit) {
        List<ScanSession> sessions = new ArrayList<>();
        String sql = """
            SELECT id, target_url, scan_timestamp, auth_type, total_vulnerabilities, 
                   critical_count, high_count, medium_count, low_count, security_score, 
                   scan_duration_ms, status
            FROM scan_sessions
            ORDER BY scan_timestamp DESC
            LIMIT ?
        """;
        
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, limit);
            ResultSet rs = stmt.executeQuery();
            
            while (rs.next()) {
                sessions.add(new ScanSession(
                    rs.getLong("id"),
                    rs.getString("target_url"),
                    rs.getTimestamp("scan_timestamp").toLocalDateTime(),
                    rs.getString("auth_type"),
                    rs.getInt("total_vulnerabilities"),
                    rs.getInt("critical_count"),
                    rs.getInt("high_count"),
                    rs.getInt("medium_count"),
                    rs.getInt("low_count"),
                    rs.getInt("security_score"),
                    rs.getLong("scan_duration_ms"),
                    rs.getString("status")
                ));
            }
        } catch (SQLException e) {
            Logger.getInstance().error("Database", "Failed to get scan history", e.getMessage());
        }
        
        return sessions;
    }
    
    public List<Vulnerability> getVulnerabilitiesForSession(long sessionId) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        String sql = """
            SELECT type, severity, endpoint, description, cwe_id, cvss_score, 
                   remediation, evidence, discovered_at
            FROM vulnerabilities
            WHERE session_id = ?
            ORDER BY discovered_at DESC
        """;
        
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setLong(1, sessionId);
            ResultSet rs = stmt.executeQuery();
            
            while (rs.next()) {
                vulnerabilities.add(new Vulnerability(
                    rs.getString("type"),
                    rs.getString("severity"),
                    rs.getString("endpoint"),
                    rs.getString("description"),
                    rs.getString("cwe_id"),
                    rs.getDouble("cvss_score"),
                    rs.getString("remediation"),
                    rs.getString("evidence")
                ));
            }
        } catch (SQLException e) {
            Logger.getInstance().error("Database", "Failed to get vulnerabilities for session", e.getMessage());
        }
        
        return vulnerabilities;
    }
    
    public void logAuditEvent(String eventType, String userAction, String targetUrl, String details) {
        String sql = """
            INSERT INTO audit_log (event_type, user_action, target_url, timestamp, details, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """;
        
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, eventType);
            stmt.setString(2, userAction);
            stmt.setString(3, targetUrl);
            stmt.setTimestamp(4, Timestamp.valueOf(LocalDateTime.now()));
            stmt.setString(5, details);
            stmt.setString(6, "localhost"); // Since we only allow localhost testing
            stmt.setString(7, "VaultScope-Desktop");
            stmt.executeUpdate();
        } catch (SQLException e) {
            Logger.getInstance().error("Database", "Failed to log audit event", e.getMessage());
        }
    }
    
    public void saveSetting(String key, String value) {
        String sql = """
            INSERT OR REPLACE INTO settings (key, value, updated_at)
            VALUES (?, ?, ?)
        """;
        
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, key);
            stmt.setString(2, value);
            stmt.setTimestamp(3, Timestamp.valueOf(LocalDateTime.now()));
            stmt.executeUpdate();
        } catch (SQLException e) {
            Logger.getInstance().error("Database", "Failed to save setting", e.getMessage());
        }
    }
    
    public String getSetting(String key, String defaultValue) {
        String sql = "SELECT value FROM settings WHERE key = ?";
        
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, key);
            ResultSet rs = stmt.executeQuery();
            
            if (rs.next()) {
                return rs.getString("value");
            }
        } catch (SQLException e) {
            Logger.getInstance().error("Database", "Failed to get setting", e.getMessage());
        }
        
        return defaultValue;
    }
    
    private int countVulnerabilitiesBySeverity(List<Vulnerability> vulnerabilities, String severity) {
        return (int) vulnerabilities.stream()
            .filter(v -> v.getSeverity().equalsIgnoreCase(severity))
            .count();
    }
    
    public void close() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
            }
        } catch (SQLException e) {
            Logger.getInstance().error("Database", "Failed to close database connection", e.getMessage());
        }
    }
    
    public static class ScanSession {
        private final long id;
        private final String targetUrl;
        private final LocalDateTime scanTimestamp;
        private final String authType;
        private final int totalVulnerabilities;
        private final int criticalCount;
        private final int highCount;
        private final int mediumCount;
        private final int lowCount;
        private final int securityScore;
        private final long scanDurationMs;
        private final String status;
        
        public ScanSession(long id, String targetUrl, LocalDateTime scanTimestamp, String authType,
                          int totalVulnerabilities, int criticalCount, int highCount, int mediumCount,
                          int lowCount, int securityScore, long scanDurationMs, String status) {
            this.id = id;
            this.targetUrl = targetUrl;
            this.scanTimestamp = scanTimestamp;
            this.authType = authType;
            this.totalVulnerabilities = totalVulnerabilities;
            this.criticalCount = criticalCount;
            this.highCount = highCount;
            this.mediumCount = mediumCount;
            this.lowCount = lowCount;
            this.securityScore = securityScore;
            this.scanDurationMs = scanDurationMs;
            this.status = status;
        }
        
        // Getters
        public long getId() { return id; }
        public String getTargetUrl() { return targetUrl; }
        public LocalDateTime getScanTimestamp() { return scanTimestamp; }
        public String getAuthType() { return authType; }
        public int getTotalVulnerabilities() { return totalVulnerabilities; }
        public int getCriticalCount() { return criticalCount; }
        public int getHighCount() { return highCount; }
        public int getMediumCount() { return mediumCount; }
        public int getLowCount() { return lowCount; }
        public int getSecurityScore() { return securityScore; }
        public long getScanDurationMs() { return scanDurationMs; }
        public String getStatus() { return status; }
    }
}