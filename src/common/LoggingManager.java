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
}
