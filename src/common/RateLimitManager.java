package common;

import java.util.concurrent.*;
import java.util.logging.Logger;

/**
 * Comprehensive Rate Limiting and DoS Protection Manager
 * Provides protection against connection flooding, request spam, brute force attacks,
 * and bandwidth abuse with automatic IP blacklisting capabilities.
 */
public class RateLimitManager {
    private static final Logger logger = LoggingManager.getLogger(RateLimitManager.class.getName());
    
    private static final int MAX_CONNECTIONS_PER_IP = 5;
    private static final int MAX_REQUESTS_PER_MINUTE = 60;
    private static final int MAX_LOGIN_ATTEMPTS_PER_HOUR = 10;
    private static final long BANDWIDTH_LIMIT_BYTES_PER_SEC = 1024 * 1024; // 1MB/s per connection
    private static final int BLACKLIST_DURATION_MINUTES = 30;
    
    private final ConcurrentHashMap<String, Integer> activeConnections = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, ConcurrentLinkedQueue<Long>> requestRates = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, ConcurrentLinkedQueue<Long>> loginAttempts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, BandwidthTracker> bandwidthTrackers = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> blacklistedIPs = new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleanupService = Executors.newSingleThreadScheduledExecutor();
    
    public RateLimitManager() {
        cleanupService.scheduleAtFixedRate(this::cleanup, 1, 1, TimeUnit.MINUTES);
        
        LoggingManager.logSecurity(logger, "Rate Limit Manager initialized - " +
                                 "Max connections per IP: " + MAX_CONNECTIONS_PER_IP +
                                 ", Max requests per minute: " + MAX_REQUESTS_PER_MINUTE +
                                 ", Max login attempts per hour: " + MAX_LOGIN_ATTEMPTS_PER_HOUR);
    }

    public boolean allowConnection(String clientIP) {
        if (isBlacklisted(clientIP)) {
            LoggingManager.logSecurity(logger, "SECURITY ALERT: Connection blocked from blacklisted IP: " + clientIP);
            return false;
        }
        
        int currentConnections = activeConnections.getOrDefault(clientIP, 0);
        if (currentConnections >= MAX_CONNECTIONS_PER_IP) {
            LoggingManager.logSecurity(logger, "SECURITY ALERT: Connection limit exceeded for IP: " + clientIP + 
                                     " (" + currentConnections + "/" + MAX_CONNECTIONS_PER_IP + ")");
            
            recordSuspiciousActivity(clientIP, "Connection limit exceeded");
            return false;
        }
        
        activeConnections.put(clientIP, currentConnections + 1);
        LoggingManager.logSecurity(logger, "Connection allowed for IP: " + clientIP + 
                                 " (active: " + (currentConnections + 1) + ")");
        return true;
    }
    
    public void releaseConnection(String clientIP) {
        activeConnections.compute(clientIP, (ip, count) -> {
            if (count != null && count > 0) {
                int newCount = count - 1;
                if (newCount == 0) {
                    return null;
                }
                return newCount;
            }
            return null;
        });
        
        LoggingManager.logSecurity(logger, "Connection released for IP: " + clientIP);
    }

    public boolean allowRequest(String clientIP) {
        if (isBlacklisted(clientIP)) {
            return false;
        }
        
        long now = System.currentTimeMillis();
        ConcurrentLinkedQueue<Long> timestamps = requestRates.computeIfAbsent(clientIP, 
                                                k -> new ConcurrentLinkedQueue<>());
        
        timestamps.removeIf(timestamp -> now - timestamp > 60000);
        
        if (timestamps.size() >= MAX_REQUESTS_PER_MINUTE) {
            LoggingManager.logSecurity(logger, "SECURITY ALERT: Request rate limit exceeded for IP: " + clientIP +
                                     " (" + timestamps.size() + "/" + MAX_REQUESTS_PER_MINUTE + ")");
            
            recordSuspiciousActivity(clientIP, "Request rate limit exceeded");
            return false;
        }
        
        timestamps.offer(now);
        return true;
    }

    public boolean allowLoginAttempt(String clientIP) {
        if (isBlacklisted(clientIP)) {
            return false;
        }
        
        long now = System.currentTimeMillis();
        ConcurrentLinkedQueue<Long> attempts = loginAttempts.computeIfAbsent(clientIP, 
                                              k -> new ConcurrentLinkedQueue<>());
        
        attempts.removeIf(timestamp -> now - timestamp > 3600000);
        
        if (attempts.size() >= MAX_LOGIN_ATTEMPTS_PER_HOUR) {
            LoggingManager.logSecurity(logger, "SECURITY ALERT: Login attempt limit exceeded for IP: " + clientIP +
                                     " (" + attempts.size() + "/" + MAX_LOGIN_ATTEMPTS_PER_HOUR + ")");
            
            blacklistIP(clientIP, "Excessive login attempts");
            return false;
        }
        
        attempts.offer(now);
        return true;
    }

    public boolean allowBandwidth(String clientIP, int bytesToTransfer) {
        BandwidthTracker tracker = bandwidthTrackers.computeIfAbsent(clientIP, 
                                  k -> new BandwidthTracker());
        
        return tracker.allowTransfer(bytesToTransfer);
    }
    
    public void recordBandwidthUsage(String clientIP, int bytesTransferred) {
        BandwidthTracker tracker = bandwidthTrackers.computeIfAbsent(clientIP, 
                                  k -> new BandwidthTracker());
        tracker.recordTransfer(bytesTransferred);
    }
    
    public boolean isBlacklisted(String clientIP) {
        Long blacklistExpiry = blacklistedIPs.get(clientIP);
        if (blacklistExpiry != null) {
            if (System.currentTimeMillis() < blacklistExpiry) {
                return true;
            } else {
                blacklistedIPs.remove(clientIP);
                LoggingManager.logSecurity(logger, "IP removed from blacklist (expired): " + clientIP);
            }
        }
        return false;
    }

    public void blacklistIP(String clientIP, String reason) {
        long expiryTime = System.currentTimeMillis() + (BLACKLIST_DURATION_MINUTES * 60 * 1000);
        blacklistedIPs.put(clientIP, expiryTime);
        
        LoggingManager.logSecurity(logger, "SECURITY ALERT: IP blacklisted for " + 
                                 BLACKLIST_DURATION_MINUTES + " minutes: " + clientIP + 
                                 " (Reason: " + reason + ")");
        
        activeConnections.remove(clientIP);
    }

    private void recordSuspiciousActivity(String clientIP, String activity) {
        LoggingManager.logSecurity(logger, "SUSPICIOUS ACTIVITY from IP " + clientIP + ": " + activity);
        
    }

    public RateLimitStats getStats() {
        return new RateLimitStats(
            activeConnections.size(),
            requestRates.size(),
            loginAttempts.size(),
            blacklistedIPs.size()
        );
    }

    private void cleanup() {
        long now = System.currentTimeMillis();
        int cleanupCount = 0;
        
        for (ConcurrentLinkedQueue<Long> timestamps : requestRates.values()) {
            int sizeBefore = timestamps.size();
            timestamps.removeIf(timestamp -> now - timestamp > 60000);
            cleanupCount += sizeBefore - timestamps.size();
        }
    
        for (ConcurrentLinkedQueue<Long> attempts : loginAttempts.values()) {
            int sizeBefore = attempts.size();
            attempts.removeIf(timestamp -> now - timestamp > 3600000);
            cleanupCount += sizeBefore - attempts.size();
        }
        
        int blacklistBefore = blacklistedIPs.size();
        blacklistedIPs.entrySet().removeIf(entry -> now >= entry.getValue());
        cleanupCount += blacklistBefore - blacklistedIPs.size();
        
        bandwidthTrackers.entrySet().removeIf(entry -> entry.getValue().isInactive(now));
        
        if (cleanupCount > 0) {
            LoggingManager.logSecurity(logger, "Rate limit cleanup completed - removed " + cleanupCount + " expired entries");
        }
    }

    public void shutdown() {
        cleanupService.shutdown();
        try {
            if (!cleanupService.awaitTermination(5, TimeUnit.SECONDS)) {
                cleanupService.shutdownNow();
            }
        } catch (InterruptedException e) {
            cleanupService.shutdownNow();
            Thread.currentThread().interrupt();
        }
        LoggingManager.logSecurity(logger, "Rate Limit Manager shutdown");
    }
    
    private static class BandwidthTracker {
        private final ConcurrentLinkedQueue<TransferRecord> transfers = new ConcurrentLinkedQueue<>();
        private volatile long lastActivity = System.currentTimeMillis();
        
        public boolean allowTransfer(int bytes) {
            long now = System.currentTimeMillis();
            
            transfers.removeIf(record -> now - record.timestamp > 1000);
            
            long currentBandwidth = transfers.stream()
                                           .mapToLong(record -> record.bytes)
                                           .sum();
            
            return (currentBandwidth + bytes) <= BANDWIDTH_LIMIT_BYTES_PER_SEC;
        }
        
        public void recordTransfer(int bytes) {
            long now = System.currentTimeMillis();
            transfers.offer(new TransferRecord(now, bytes));
            lastActivity = now;
        }
        
        public boolean isInactive(long currentTime) {
            return currentTime - lastActivity > 300000; // 5 minutes
        }
        
        private static class TransferRecord {
            final long timestamp;
            final int bytes;
            
            TransferRecord(long timestamp, int bytes) {
                this.timestamp = timestamp;
                this.bytes = bytes;
            }
        }
    }

    public static class RateLimitStats {
        public final int activeIPs;
        public final int trackedRequestIPs;
        public final int trackedLoginIPs;
        public final int blacklistedIPs;
        
        public RateLimitStats(int activeIPs, int trackedRequestIPs, int trackedLoginIPs, int blacklistedIPs) {
            this.activeIPs = activeIPs;
            this.trackedRequestIPs = trackedRequestIPs;
            this.trackedLoginIPs = trackedLoginIPs;
            this.blacklistedIPs = blacklistedIPs;
        }
        
        @Override
        public String toString() {
            return "RateLimitStats{" +
                   "activeIPs=" + activeIPs +
                   ", trackedRequestIPs=" + trackedRequestIPs +
                   ", trackedLoginIPs=" + trackedLoginIPs +
                   ", blacklistedIPs=" + blacklistedIPs +
                   '}';
        }
    }
}
