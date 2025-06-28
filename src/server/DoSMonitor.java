package server;

import common.*;
import java.util.concurrent.*;
import java.util.logging.Logger;

/**
 * DoS Attack Monitoring and Detection System
 * Monitors for various types of attacks and triggers automated responses
 */
public class DoSMonitor {
    private static final Logger logger = LoggingManager.getLogger(DoSMonitor.class.getName());
    
    private final RateLimitManager rateLimitManager;
    private final ScheduledExecutorService monitorService = Executors.newSingleThreadScheduledExecutor();
    
    private static final int HIGH_CONNECTION_THRESHOLD = 50;
    private static final int HIGH_REQUEST_RATE_THRESHOLD = 100;
    private static final int BLACKLIST_ALERT_THRESHOLD = 5;
    
    public DoSMonitor(RateLimitManager rateLimitManager) {
        this.rateLimitManager = rateLimitManager;
        
        monitorService.scheduleAtFixedRate(this::performSecurityCheck, 30, 30, TimeUnit.SECONDS);
        
        LoggingManager.logSecurity(logger, "DoS Monitor started - monitoring for attacks");
    }

    private void performSecurityCheck() {
        try {
            RateLimitManager.RateLimitStats stats = rateLimitManager.getStats();
            
            if (stats.activeIPs > HIGH_CONNECTION_THRESHOLD) {
                LoggingManager.logSecurity(logger, 
                    "SECURITY ALERT: High connection count detected - " + stats.activeIPs + 
                    " active IPs (threshold: " + HIGH_CONNECTION_THRESHOLD + ")");
                
                considerAutomatedResponse("HIGH_CONNECTIONS", stats);
            }
            
            if (stats.blacklistedIPs > BLACKLIST_ALERT_THRESHOLD) {
                LoggingManager.logSecurity(logger, 
                    "SECURITY ALERT: Multiple IPs blacklisted - " + stats.blacklistedIPs + 
                    " blacklisted IPs (threshold: " + BLACKLIST_ALERT_THRESHOLD + ")");
                
                considerAutomatedResponse("HIGH_BLACKLIST", stats);
            }
            
            if (stats.activeIPs > 0 || stats.blacklistedIPs > 0 || stats.trackedRequestIPs > 0) {
                LoggingManager.logSecurity(logger, "Security monitoring status: " + stats.toString());
            }
            
        } catch (Exception e) {
            logger.warning("Error during security check: " + e.getMessage());
        }
    }
    

    private void considerAutomatedResponse(String alertType, RateLimitManager.RateLimitStats stats) {
        
        LoggingManager.logSecurity(logger, 
            "AUTOMATED RESPONSE CONSIDERATION: " + alertType + " - Stats: " + stats.toString());
        
        switch (alertType) {
            case "HIGH_CONNECTIONS":
                LoggingManager.logSecurity(logger, "Considering stricter connection limits due to high connection count");
                break;
                
            case "HIGH_BLACKLIST":
                LoggingManager.logSecurity(logger, "Multiple IPs blacklisted - possible coordinated attack");
                break;
                
            default:
                LoggingManager.logSecurity(logger, "Unknown alert type for automated response: " + alertType);
        }
    }

    public void triggerSecurityCheck() {
        performSecurityCheck();
    }
    
    public String getSecurityStatus() {
        RateLimitManager.RateLimitStats stats = rateLimitManager.getStats();
        StringBuilder status = new StringBuilder();
        
        status.append("=== DoS Protection Status ===\n");
        status.append("Active IPs: ").append(stats.activeIPs).append("\n");
        status.append("Tracked Request IPs: ").append(stats.trackedRequestIPs).append("\n");
        status.append("Tracked Login IPs: ").append(stats.trackedLoginIPs).append("\n");
        status.append("Blacklisted IPs: ").append(stats.blacklistedIPs).append("\n");
        
        // Add threat level assessment
        String threatLevel = assessThreatLevel(stats);
        status.append("Threat Level: ").append(threatLevel).append("\n");
        
        return status.toString();
    }

    private String assessThreatLevel(RateLimitManager.RateLimitStats stats) {
        if (stats.blacklistedIPs >= BLACKLIST_ALERT_THRESHOLD || 
            stats.activeIPs >= HIGH_CONNECTION_THRESHOLD) {
            return "HIGH";
        } else if (stats.blacklistedIPs > 1 || stats.activeIPs > 20) {
            return "MEDIUM";
        } else if (stats.activeIPs > 5 || stats.trackedRequestIPs > 10) {
            return "LOW";
        } else {
            return "NORMAL";
        }
    }
    
    public void shutdown() {
        monitorService.shutdown();
        try {
            if (!monitorService.awaitTermination(5, TimeUnit.SECONDS)) {
                monitorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            monitorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
        LoggingManager.logSecurity(logger, "DoS Monitor shutdown");
    }
}
