package common;

import java.io.File;
import java.io.FileInputStream;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class LoggingManager {
    private static final Logger logger = Logger.getLogger(LoggingManager.class.getName());
    private static boolean initialized = false;
  
    public static void initialize() {
        if (initialized) {
            return;
        }
        
        try {
            File logsDir = new File("logs");
            if (!logsDir.exists()) {
                logsDir.mkdir();
            }
            
            File dataDir = new File("data");
            if (!dataDir.exists()) {
                dataDir.mkdir();
            }
            
            boolean configLoaded = false;
            
            LogManager logManager = LogManager.getLogManager();
            File configFile = new File("resources/logging.properties");
            if (configFile.exists()) {
                try (FileInputStream fis = new FileInputStream(configFile)) {
                    logManager.readConfiguration(fis);
                    configLoaded = true;
                }
            } else {
                // Using default logging configuration
            }
            
            if (!configLoaded) {
                Handler fileHandler = new FileHandler("logs/secure_transfer_%u_%g.log", 5000000, 10, true);
                fileHandler.setFormatter(new SimpleFormatter());
                fileHandler.setLevel(Level.ALL);
                
                Logger rootLogger = Logger.getLogger("");
                rootLogger.addHandler(fileHandler);
                rootLogger.setLevel(Level.INFO);
                
                // Set specific package levels
                Logger.getLogger("client").setLevel(Level.FINE);
                Logger.getLogger("server").setLevel(Level.FINE);
                Logger.getLogger("common").setLevel(Level.FINE);
            }
            
            initialized = true;
            logger.info("Logging system initialized");
        } catch (Exception e) {
            System.err.println("Error initializing logging: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    public static Logger getLogger(String name) {
        Logger logger = Logger.getLogger(name);
        return logger;
    }
    
    public static void logSecurity(Logger logger, String message) {
        logger.log(Level.INFO, "[SECURITY] " + message);
    }
    
    public static void logCrypto(Logger logger, String operation, String details) {
        logger.log(Level.FINE, "[CRYPTO] " + operation + ": " + details);
    }
    
    public static void logTransfer(Logger logger, String transferId, String event, String details) {
        logger.log(Level.INFO, "[TRANSFER:" + transferId + "] " + event + (details != null ? ": " + details : ""));
    }
    
    /**
     * Log Perfect Forward Secrecy (PFS) related security operations
     * These logs capture the complete PFS lifecycle for security auditing
     */
    public static void logPFS(Logger logger, String transferId, String phase, String operation, String details) {
        String logMessage = "[PFS:" + transferId + "] Phase:" + phase + " | " + operation;
        if (details != null && !details.isEmpty()) {
            logMessage += " | " + details;
        }
        logger.log(Level.INFO, logMessage);
    }
    
    /**
     * Log detailed step-by-step security operations for complete audit trail
     */
    public static void logSecurityStep(Logger logger, String transferId, String participant, 
                                     String step, String operation, String details) {
        String logMessage = "[SECURITY-STEP:" + transferId + "] " + participant + " | Step:" + step + 
                           " | " + operation;
        if (details != null && !details.isEmpty()) {
            logMessage += " | " + details;
        }
        logger.log(Level.INFO, logMessage);
    }
    
    /**
     * Log cryptographic operations with enhanced details for security monitoring
     */
    public static void logCryptoOperation(Logger logger, String transferId, String operation, 
                                        String algorithm, String keyInfo, String result) {
        String logMessage = "[CRYPTO-OP:" + transferId + "] " + operation + " | Algorithm:" + algorithm;
        if (keyInfo != null && !keyInfo.isEmpty()) {
            logMessage += " | KeyInfo:" + keyInfo;
        }
        if (result != null && !result.isEmpty()) {
            logMessage += " | Result:" + result;
        }
        logger.log(Level.INFO, logMessage);
    }
    
    /**
     * Log key lifecycle events for PFS compliance monitoring
     */
    public static void logKeyLifecycle(Logger logger, String transferId, String keyType, 
                                     String operation, String details) {
        String logMessage = "[KEY-LIFECYCLE:" + transferId + "] " + keyType + " | " + operation;
        if (details != null && !details.isEmpty()) {
            logMessage += " | " + details;
        }
        logger.log(Level.INFO, logMessage);
    }
    
    /**
     * Log authentication and verification steps
     */
    public static void logAuthentication(Logger logger, String transferId, String participant, 
                                       String operation, String method, String result) {
        String logMessage = "[AUTH:" + transferId + "] " + participant + " | " + operation + 
                           " | Method:" + method + " | Result:" + result;
        logger.log(Level.INFO, logMessage);
    }
    
    /**
     * Log memory security operations (key wiping, secure cleanup)
     */
    public static void logMemorySecurity(Logger logger, String transferId, String operation, String details) {
        String logMessage = "[MEMORY-SEC:" + transferId + "] " + operation;
        if (details != null && !details.isEmpty()) {
            logMessage += " | " + details;
        }
        logger.log(Level.INFO, logMessage);
    }
    
    /**
     * Log end-to-end security flow summary for easy tracking
     */
    public static void logSecuritySummary(Logger logger, String transferId, String participant, 
                                        String phase, String status, String securityLevel) {
        String logMessage = "[SECURITY-SUMMARY:" + transferId + "] " + participant + " | Phase:" + phase + 
                           " | Status:" + status + " | SecurityLevel:" + securityLevel;
        logger.log(Level.INFO, logMessage);
    }
}
