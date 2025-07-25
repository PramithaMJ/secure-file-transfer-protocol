package common;

import java.security.SecureRandom;
import java.util.concurrent.*;
import java.util.logging.Logger;

/**
 * Manages user sessions with automatic timeout and cleanup
 * Provides secure session token generation and validation
 */
public class SessionManager {
    private static final Logger logger = LoggingManager.getLogger(SessionManager.class.getName());
    
    // Session timeout
    private static final long SESSION_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes
    
    // Maximum session duration
    private static final long MAX_SESSION_DURATION_MS = 8 * 60 * 60 * 1000; // 8 hours
    
    // Warning time before session expires
    private static final long SESSION_WARNING_MS = 5 * 60 * 1000; // 5 minutes
    
    private final ConcurrentHashMap<String, Session> activeSessions = new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleanupService = Executors.newSingleThreadScheduledExecutor();
    private final SecureRandom secureRandom = new SecureRandom();
    
    public SessionManager() {
        cleanupService.scheduleAtFixedRate(this::cleanupExpiredSessions, 
                                         5, 5, TimeUnit.MINUTES);
        
        logger.info("Session Manager initialized with " +
                   "timeout: " + (SESSION_TIMEOUT_MS/1000/60) + " minutes, " +
                   "max duration: " + (MAX_SESSION_DURATION_MS/1000/60/60) + " hours");
    }
    
    public String createSession(String username) {
        LoggingManager.logSecurityStep(logger, "SESSION_TOKEN_GENERATION", 
                "Generating secure session token for user: " + username);
        String sessionToken = generateSecureToken();
        Session session = new Session(sessionToken, username);
        
        LoggingManager.logSecurityStep(logger, "USER_SESSION_CLEANUP", 
                "Removing any existing sessions for user: " + username);
        removeUserSessions(username);
        
        activeSessions.put(sessionToken, session);
        
        LoggingManager.logSession(logger, sessionToken, "CREATED", 
                "New session created for user: " + username + 
                ", with timeout: " + (SESSION_TIMEOUT_MS/1000/60) + " minutes");
        
        return sessionToken;
    }
    
    public boolean validateAndRefreshSession(String sessionToken) {
        LoggingManager.logSecurityStep(logger, "SESSION_VALIDATION", 
                "Validating session token: " + (sessionToken != null ? 
                sessionToken.substring(0, Math.min(8, sessionToken.length())) + "..." : "null"));
                
        if (sessionToken == null || sessionToken.trim().isEmpty()) {
            LoggingManager.logSecurity(logger, LoggingManager.SecurityLevel.WARNING, 
                    "Attempted to validate null or empty session token");
            return false;
        }
        
        Session session = activeSessions.get(sessionToken);
        
        if (session == null) {
            LoggingManager.logSecurity(logger, LoggingManager.SecurityLevel.WARNING, 
                    "Invalid session token attempted: " + 
                    sessionToken.substring(0, Math.min(8, sessionToken.length())) + "... - session not found");
            return false;
        }
        
        long now = System.currentTimeMillis();
        
        if (now - session.getLastActivity() > SESSION_TIMEOUT_MS) {
            LoggingManager.logSession(logger, sessionToken, "EXPIRED_INACTIVITY", 
                    "Session expired due to " + (SESSION_TIMEOUT_MS/1000/60) + 
                    " minutes of inactivity for user: " + session.getUsername());
            removeSession(sessionToken);
            return false;
        }
        
        if (now - session.getCreatedTime() > MAX_SESSION_DURATION_MS) {
            LoggingManager.logSession(logger, sessionToken, "EXPIRED_MAX_DURATION", 
                    "Session expired due to maximum duration (" + 
                    (MAX_SESSION_DURATION_MS/1000/60/60) + " hours) for user: " + 
                    session.getUsername());
            removeSession(sessionToken);
            return false;
        }
        
        LoggingManager.logSecurityStep(logger, "SESSION_REFRESH", 
                "Refreshing activity timestamp for session: " + 
                sessionToken.substring(0, Math.min(8, sessionToken.length())) + "...");
        session.updateLastActivity();
        
        return true;
    }

    public Session getSession(String sessionToken) {
        if (sessionToken == null) {
            return null;
        }
        return activeSessions.get(sessionToken);
    }
    
    public boolean isSessionExpiringsoon(String sessionToken) {
        Session session = getSession(sessionToken);
        if (session == null) {
            return false;
        }
        
        long now = System.currentTimeMillis();
        long timeUntilExpiry = SESSION_TIMEOUT_MS - (now - session.getLastActivity());
        
        return timeUntilExpiry <= SESSION_WARNING_MS && timeUntilExpiry > 0;
    }

    public boolean removeSession(String sessionToken) {
        if (sessionToken == null) {
            LoggingManager.logSecurity(logger, LoggingManager.SecurityLevel.WARNING, 
                    "Attempted to remove null session token");
            return false;
        }
        
        LoggingManager.logSecurityStep(logger, "SESSION_REMOVAL", 
                "Removing session: " + sessionToken.substring(0, Math.min(8, sessionToken.length())) + "...");
        
        Session session = activeSessions.remove(sessionToken);
        
        if (session != null) {
            LoggingManager.logSession(logger, sessionToken, "REMOVED", 
                    "Session removed for user: " + session.getUsername());
            return true;
        }
        
        return false;
    }

    public void removeUserSessions(String username) {
        LoggingManager.logSecurityStep(logger, "USER_SESSION_CLEANUP", 
                "Removing all existing sessions for user: " + username);
        
        activeSessions.entrySet().removeIf(entry -> {
            if (entry.getValue().getUsername().equals(username)) {
                LoggingManager.logSession(logger, entry.getKey(), "REMOVED", 
                        "Removing existing session for user: " + username + 
                        " due to new login");
                return true;
            }
            return false;
        });
    }

    public int getActiveSessionCount() {
        return activeSessions.size();
    }

    public long getSessionTimeoutMs() {
        return SESSION_TIMEOUT_MS;
    }

    private String generateSecureToken() {
        byte[] tokenBytes = new byte[32]; // 256 bits
        secureRandom.nextBytes(tokenBytes);
        
        StringBuilder sb = new StringBuilder();
        for (byte b : tokenBytes) {
            sb.append(String.format("%02x", b));
        }
        
        return sb.toString();
    }
    
    private void cleanupExpiredSessions() {
        LoggingManager.logSecurityStep(logger, "SESSION_CLEANUP", 
                "Starting periodic cleanup of expired sessions");
        
        long now = System.currentTimeMillis();
        int removedCount = 0;
        
        for (var iterator = activeSessions.entrySet().iterator(); iterator.hasNext();) {
            var entry = iterator.next();
            Session session = entry.getValue();
            String token = entry.getKey();
            
            boolean expiredInactivity = (now - session.getLastActivity()) > SESSION_TIMEOUT_MS;
            boolean expiredDuration = (now - session.getCreatedTime()) > MAX_SESSION_DURATION_MS;
            
            if (expiredInactivity || expiredDuration) {
                String reason = expiredInactivity ? "inactivity timeout" : "maximum duration reached";
                LoggingManager.logSession(logger, token, "AUTO_CLEANUP", 
                        "Cleaning up expired session for user: " + session.getUsername() +
                        " due to " + reason);
                iterator.remove();
                removedCount++;
            }
        }
        
        if (removedCount > 0) {
            logger.info("Cleaned up " + removedCount + " expired sessions");
        }
    }
    
    public void shutdown() {
        logger.info("Shutting down Session Manager...");
        cleanupService.shutdown();
        try {
            if (!cleanupService.awaitTermination(5, TimeUnit.SECONDS)) {
                cleanupService.shutdownNow();
            }
        } catch (InterruptedException e) {
            cleanupService.shutdownNow();
            Thread.currentThread().interrupt();
        }
        
        int sessionCount = activeSessions.size();
        activeSessions.clear();
        
        logger.info("Session Manager shutdown complete. Cleared " + sessionCount + " active sessions");
    }
}
