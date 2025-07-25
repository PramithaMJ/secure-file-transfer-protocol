package utils;

import common.LoggingManager;
import java.util.logging.Logger;

/**
 * Utility class to test and validate the security logging functionality
 */
public class LoggingTest {
    private static final Logger logger = LoggingManager.getLogger(LoggingTest.class.getName());
    
    public static void main(String[] args) {
        try {
            System.out.println("Starting logging test...");
            
            LoggingManager.initialize();
            
            testAllLoggingMethods();
            
            System.out.println("Logging test completed. Please check the log files:");
            System.out.println("1. Main logs: logs/secure_transfer_*.log");
            System.out.println("2. Security logs: logs/security/security_flow_*.log");
            
        } catch (Exception e) {
            System.err.println("Logging test failed with error: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static void testAllLoggingMethods() {
        String testUsername = "test_user";
        String testSessionId = "test_session_123";
        String testTransferId = "test_transfer_456";
        String testKeyId = "test_key_789";
        String testResource = "test_file.txt";
        
        // Test basic security logging
        LoggingManager.logSecurity(logger, "Basic security log test message");
        
        // Test security levels
        LoggingManager.logSecurity(logger, LoggingManager.SecurityLevel.DEBUG, "Debug level security message");
        LoggingManager.logSecurity(logger, LoggingManager.SecurityLevel.INFO, "Info level security message");
        LoggingManager.logSecurity(logger, LoggingManager.SecurityLevel.WARNING, "Warning level security message");
        LoggingManager.logSecurity(logger, LoggingManager.SecurityLevel.CRITICAL, "Critical level security message");
        LoggingManager.logSecurity(logger, LoggingManager.SecurityLevel.ALERT, "Alert level security message");
        
        // Test security steps
        LoggingManager.logSecurityStep(logger, "AUTHENTICATION", "Starting user authentication flow");
        LoggingManager.logSecurityStep(logger, "KEY_EXCHANGE", "Performing Diffie-Hellman key exchange");
        
        // Test crypto operations
        LoggingManager.logCrypto(logger, "AES_ENCRYPT", "Encrypting data with AES-256-CBC");
        LoggingManager.logCrypto(logger, "RSA_DECRYPT", "Decrypting symmetric key with RSA private key");
        
        // Test authentication logging
        LoggingManager.logAuthentication(logger, testUsername, true, "Password authentication successful");
        LoggingManager.logAuthentication(logger, "invalid_user", false, "User not found in database");
        
        // Test transfer logging
        LoggingManager.logTransfer(logger, testTransferId, "STARTED", "Transfer initiated by " + testUsername);
        LoggingManager.logTransfer(logger, testTransferId, "CHUNK_SENT", "Encrypted chunk 1/5 sent");
        LoggingManager.logTransfer(logger, testTransferId, "COMPLETED", "All chunks transferred and verified");
        
        // Test key management
        LoggingManager.logKeyManagement(logger, "GENERATED", testKeyId, "Generated new AES-256 key");
        LoggingManager.logKeyManagement(logger, "ROTATED", testKeyId, "Key rotation performed for user " + testUsername);
        
        // Test signature logging
        LoggingManager.logSignature(logger, "VERIFY_CHUNK", true, "Chunk 3 signature verified successfully");
        LoggingManager.logSignature(logger, "VERIFY_MESSAGE", false, "Signature validation failed - corrupted data");
        
        // Test session logging
        LoggingManager.logSession(logger, testSessionId, "CREATED", "New session for user " + testUsername);
        LoggingManager.logSession(logger, testSessionId, "REFRESHED", "Session token refreshed, extended by 30 minutes");
        LoggingManager.logSession(logger, testSessionId, "EXPIRED", "Session timed out after inactivity");
        
        // Test access control
        LoggingManager.logAccessControl(logger, testUsername, testResource, true, "User has READ permission");
        LoggingManager.logAccessControl(logger, testUsername, "/admin/config.xml", false, "Permission denied: Requires ADMIN role");
        
        // Test protocol logging
        LoggingManager.logProtocol(logger, "TLS", "HANDSHAKE", "TLSv1.3 handshake completed, cipher: TLS_AES_256_GCM_SHA384");
        LoggingManager.logProtocol(logger, "SFTP", "CONNECT", "Secure channel established");
    }
}
