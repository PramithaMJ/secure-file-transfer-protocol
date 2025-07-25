package common;

import java.io.File;
import java.io.FileInputStream;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class LoggingManager {
    private static final Logger logger = Logger.getLogger(LoggingManager.class.getName());
    private static boolean initialized = false;
    
    public enum SecurityLevel {
        DEBUG, INFO, WARNING, CRITICAL, ALERT
    }
  
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
            
            File securityLogsDir = new File("logs/security");
            if (!securityLogsDir.exists()) {
                boolean created = securityLogsDir.mkdirs();
                if (!created) {
                    System.err.println("Failed to create security logs directory: " + securityLogsDir.getAbsolutePath());
                } else {
                    System.out.println("Successfully created security logs directory: " + securityLogsDir.getAbsolutePath());
                }
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
            }
            
            if (!configLoaded) {
                Handler fileHandler = new FileHandler("logs/secure_transfer_%u_%g.log", 5000000, 10, true);
                fileHandler.setFormatter(new SimpleFormatter());
                fileHandler.setLevel(Level.ALL);
                
                Handler securityHandler;
                try {
                    securityHandler = new FileHandler("logs/security/security_flow_%u_%g.log", 5000000, 10, true);
                    securityHandler.setFormatter(new SimpleFormatter());
                    securityHandler.setLevel(Level.ALL);
                } catch (Exception e) {
                    System.err.println("Failed to create security log handler: " + e.getMessage());
                    e.printStackTrace();
                    securityHandler = new FileHandler("logs/security_flow_fallback_%u_%g.log", 5000000, 10, true);
                    securityHandler.setFormatter(new SimpleFormatter());
                    securityHandler.setLevel(Level.ALL);
                }
                
                Logger rootLogger = Logger.getLogger("");
                rootLogger.addHandler(fileHandler);
                rootLogger.setLevel(Level.INFO);
                
                Logger.getLogger("client").setLevel(Level.ALL);
                Logger.getLogger("server").setLevel(Level.ALL);
                Logger.getLogger("common").setLevel(Level.ALL);
                
                Logger securityLogger = Logger.getLogger("security");
                securityLogger.addHandler(securityHandler);
                securityLogger.setLevel(Level.ALL);
                securityLogger.setUseParentHandlers(false);
                
                for (Handler handler : securityLogger.getHandlers()) {
                    handler.setLevel(Level.ALL);
                }
            }
            
            initialized = true;
            logger.info("Logging system initialized");
            
            boolean securityLoggingVerified = verifySecurityLogging();
            logger.info("Security logging verification " + (securityLoggingVerified ? "succeeded" : "failed"));
            
            Logger secLogger = getSecurityLogger();
            secLogger.info("=== SECURITY FLOW LOGGING INITIALIZED ===");
            
            System.out.println("Main logs directory: " + new File("logs").getAbsolutePath());
            System.out.println("Security logs directory: " + new File("logs/security").getAbsolutePath());
        } catch (Exception e) {
            System.err.println("Error initializing logging: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    public static Logger getLogger(String name) {
        Logger logger = Logger.getLogger(name);
        return logger;
    }
    
    public static Logger getSecurityLogger() {
        return Logger.getLogger("security");
    }

    public static void logSecurity(Logger logger, String message) {
        logger.log(Level.INFO, "[SECURITY] " + message);
        
        Logger securityLogger = getSecurityLogger();
        try {
            if (securityLogger.getHandlers().length == 0) {
                System.out.println("WARNING: Security logger has no handlers, adding a new handler");
                Handler securityHandler = new FileHandler("logs/security/security_flow_emergency_%u_%g.log", true);
                securityHandler.setFormatter(new SimpleFormatter());
                securityLogger.addHandler(securityHandler);
            }
            securityLogger.info("[SECURITY_FLOW] " + message);
        } catch (Exception e) {
            System.err.println("Failed to log security message: " + e.getMessage());
            e.printStackTrace();
            logger.severe("SECURITY LOG FAILURE: " + e.getMessage() + " - Original message: " + message);
        }
    }

    public static void logSecurity(Logger logger, SecurityLevel level, String message) {
        Level javaLevel;
        String prefix;
        
        switch (level) {
            case DEBUG:
                javaLevel = Level.FINE;
                prefix = "[SECURITY_DEBUG]";
                break;
            case WARNING:
                javaLevel = Level.WARNING;
                prefix = "[SECURITY_WARNING]";
                break;
            case CRITICAL:
                javaLevel = Level.SEVERE;
                prefix = "[SECURITY_CRITICAL]";
                break;
            case ALERT:
                javaLevel = Level.SEVERE;
                prefix = "[SECURITY_ALERT]";
                break;
            default:
                javaLevel = Level.INFO;
                prefix = "[SECURITY_INFO]";
        }
        
        logger.log(javaLevel, prefix + " " + message);
        
        Logger securityLogger = getSecurityLogger();
        securityLogger.log(javaLevel, "[SECURITY_FLOW] " + prefix + " " + message);
    }
  
    public static void logSecurityStep(Logger logger, String stepName, String details) {
        logger.log(Level.INFO, "[SECURITY_STEP] " + stepName + ": " + details);
        
        Logger securityLogger = getSecurityLogger();
        securityLogger.info("[SECURITY_FLOW] STEP: " + stepName + " | " + details);
    }

    public static void logCrypto(Logger logger, String operation, String details) {
        logger.log(Level.FINE, "[CRYPTO] " + operation + ": " + details);
        
        Logger securityLogger = getSecurityLogger();
        securityLogger.fine("[SECURITY_FLOW] CRYPTO: " + operation + " | " + details);
    }

    public static void logAuthentication(Logger logger, String username, boolean success, String details) {
        String status = success ? "SUCCESS" : "FAILURE";
        logger.log(success ? Level.INFO : Level.WARNING, 
                  "[AUTH] " + status + " for user '" + username + "'" + 
                  (details != null ? ": " + details : ""));
        
        Logger securityLogger = getSecurityLogger();
        securityLogger.log(success ? Level.INFO : Level.WARNING, 
                         "[SECURITY_FLOW] AUTH: " + status + " | User: " + username + 
                         (details != null ? " | " + details : ""));
    }

    public static void logTransfer(Logger logger, String transferId, String event, String details) {
        logger.log(Level.INFO, "[TRANSFER:" + transferId + "] " + event + 
                  (details != null ? ": " + details : ""));
        
        Logger securityLogger = getSecurityLogger();
        securityLogger.info("[SECURITY_FLOW] TRANSFER: " + transferId + " | " + event +
                         (details != null ? " | " + details : ""));
    }
   
    public static void logKeyManagement(Logger logger, String operation, String keyId, String details) {
        logger.log(Level.INFO, "[KEY_MGMT] " + operation + " for key " + keyId + 
                  (details != null ? ": " + details : ""));
        
        Logger securityLogger = getSecurityLogger();
        securityLogger.info("[SECURITY_FLOW] KEY_MGMT: " + operation + " | KeyID: " + keyId +
                         (details != null ? " | " + details : ""));
    }
    
    public static void logSignature(Logger logger, String operation, boolean verified, String details) {
        Level level = verified ? Level.INFO : Level.WARNING;
        String status = verified ? "VALID" : "INVALID";
        
        logger.log(level, "[SIGNATURE] " + operation + ": " + status + 
                  (details != null ? " - " + details : ""));
        
        Logger securityLogger = getSecurityLogger();
        securityLogger.log(level, "[SECURITY_FLOW] SIGNATURE: " + operation + " | Status: " + status +
                        (details != null ? " | " + details : ""));
    }
    
    public static void logSession(Logger logger, String sessionId, String event, String details) {
        logger.log(Level.INFO, "[SESSION:" + sessionId + "] " + event + 
                  (details != null ? ": " + details : ""));
        
        Logger securityLogger = getSecurityLogger();
        securityLogger.info("[SECURITY_FLOW] SESSION: " + sessionId + " | " + event +
                         (details != null ? " | " + details : ""));
    }
    
    public static void logAccessControl(Logger logger, String username, String resource, boolean allowed, String details) {
        Level level = allowed ? Level.INFO : Level.WARNING;
        String decision = allowed ? "GRANTED" : "DENIED";
        
        logger.log(level, "[ACCESS] " + decision + " for user '" + username + "' to resource '" + resource + "'" +
                 (details != null ? ": " + details : ""));
        
        Logger securityLogger = getSecurityLogger();
        securityLogger.log(level, "[SECURITY_FLOW] ACCESS: " + decision + " | User: " + username + 
                        " | Resource: " + resource + (details != null ? " | " + details : ""));
    }
  
    public static void logProtocol(Logger logger, String protocolName, String step, String details) {
        logger.log(Level.INFO, "[PROTOCOL:" + protocolName + "] " + step + 
                  (details != null ? ": " + details : ""));
        
        Logger securityLogger = getSecurityLogger();
        securityLogger.info("[SECURITY_FLOW] PROTOCOL: " + protocolName + " | Step: " + step +
                         (details != null ? " | " + details : ""));
    }
 
    public static boolean verifySecurityLogging() {
        try {
            System.out.println("Verifying security logging system...");
            
            File securityDir = new File("logs/security");
            if (!securityDir.exists()) {
                System.err.println("Security logs directory does not exist, creating it...");
                boolean created = securityDir.mkdirs();
                if (!created) {
                    System.err.println("Failed to create security logs directory!");
                    return false;
                }
            }
            
            if (!securityDir.canWrite()) {
                System.err.println("Security logs directory is not writable!");
                return false;
            }
            
            Logger secLogger = getSecurityLogger();
            String testMessage = "SECURITY LOGGING TEST - " + System.currentTimeMillis();
            
            ConsoleHandler ch = new ConsoleHandler();
            ch.setLevel(Level.ALL);
            secLogger.addHandler(ch);
            
            secLogger.info(testMessage);
            
            secLogger.removeHandler(ch);
            
            System.out.println("Security logging verification complete.");
            return true;
        } catch (Exception e) {
            System.err.println("Security logging verification failed: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
}