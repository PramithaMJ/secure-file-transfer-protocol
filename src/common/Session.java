package common;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Represents a user session with creation time, last activity tracking,
 * and session management capabilities
 */
public class Session {
    private final String sessionToken;
    private final String username;
    private final long createdTime;
    private volatile long lastActivity;
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public Session(String sessionToken, String username) {
        this.sessionToken = sessionToken;
        this.username = username;
        this.createdTime = System.currentTimeMillis();
        this.lastActivity = System.currentTimeMillis();
    }

    public String getSessionToken() {
        return sessionToken;
    }

    public String getUsername() {
        return username;
    }
    
    public long getCreatedTime() {
        return createdTime;
    }

    public long getLastActivity() {
        return lastActivity;
    }
    
    public void updateLastActivity() {
        this.lastActivity = System.currentTimeMillis();
    }
    

    public long getSessionAge() {
        return System.currentTimeMillis() - createdTime;
    }
    
    public long getInactivityDuration() {
        return System.currentTimeMillis() - lastActivity;
    }

    public String getFormattedSessionAge() {
        long ageMs = getSessionAge();
        return formatDuration(ageMs);
    }

    public String getFormattedInactivityDuration() {
        long inactivityMs = getInactivityDuration();
        return formatDuration(inactivityMs);
    }
    
    public boolean isActive(long thresholdMs) {
        return getInactivityDuration() <= thresholdMs;
    }
    
    public LocalDateTime getCreatedDateTime() {
        return LocalDateTime.ofInstant(
            java.time.Instant.ofEpochMilli(createdTime),
            java.time.ZoneId.systemDefault()
        );
    }

    public LocalDateTime getLastActivityDateTime() {
        return LocalDateTime.ofInstant(
            java.time.Instant.ofEpochMilli(lastActivity),
            java.time.ZoneId.systemDefault()
        );
    }

    private String formatDuration(long durationMs) {
        long seconds = durationMs / 1000;
        long minutes = seconds / 60;
        long hours = minutes / 60;
        
        seconds %= 60;
        minutes %= 60;
        
        if (hours > 0) {
            return String.format("%dh %dm %ds", hours, minutes, seconds);
        } else if (minutes > 0) {
            return String.format("%dm %ds", minutes, seconds);
        } else {
            return String.format("%ds", seconds);
        }
    }
    
    @Override
    public String toString() {
        return "Session{" +
                "username='" + username + '\'' +
                ", created=" + getCreatedDateTime().format(DATE_FORMATTER) +
                ", lastActivity=" + getLastActivityDateTime().format(DATE_FORMATTER) +
                ", age=" + getFormattedSessionAge() +
                ", inactive=" + getFormattedInactivityDuration() +
                '}';
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        
        Session session = (Session) o;
        return sessionToken.equals(session.sessionToken);
    }
    
    @Override
    public int hashCode() {
        return sessionToken.hashCode();
    }
}
