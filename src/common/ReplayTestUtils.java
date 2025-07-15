package common;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.logging.Logger;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Utility class for testing the anti-replay protection system
 * This class allows simulation of various replay attack scenarios
 */
public class ReplayTestUtils {
    private static final Logger logger = LoggingManager.getLogger(ReplayTestUtils.class.getName());
    
    /**
     * Run a comprehensive test of the anti-replay protection system
     * This method will simulate various replay attack scenarios and report results
     */
    public static void runAntiReplayTests() {
        try {
            logger.info("Starting Anti-Replay Protection System Tests...");
            LoggingManager.logSecurity(logger, "ADMIN: Starting Anti-Replay Protection System Tests");
            
            // Generate test keys
            SecretKey testSymmetricKey = generateTestKey("AES");
            SecretKey testHmacKey = generateTestKey("HmacSHA256");
            
            // Test 1: Basic duplicate detection
            testBasicDuplicateDetection(testSymmetricKey, testHmacKey);
            
            // Test 2: Sequence validation
            testSequenceValidation(testSymmetricKey, testHmacKey);
            
            // Test 3: Transfer completion cleanup
            testTransferCompletion(testSymmetricKey, testHmacKey);
            
            // Test 4: Simulate replay attack
            testReplayAttack(testSymmetricKey, testHmacKey);
            
            logger.info("Anti-Replay Protection System Tests completed");
            LoggingManager.logSecurity(logger, "ADMIN: Anti-Replay Protection Tests completed");
            
        } catch (Exception e) {
            logger.severe("Error during anti-replay tests: " + e.getMessage());
            LoggingManager.logSecurity(logger, "ERROR: Anti-replay tests failed: " + e.getMessage());
        }
    }
    
    /**
     * Test basic duplicate detection
     */
    private static void testBasicDuplicateDetection(SecretKey symmetricKey, SecretKey hmacKey) throws Exception {
        String transferId = UUID.randomUUID().toString();
        LoggingManager.logSecurity(logger, "TEST: Basic duplicate detection - Transfer ID: " + transferId);
        
        // Create and encrypt a test chunk
        byte[] testData = "Test data for duplicate detection".getBytes();
        SecureMessage message = CryptoUtils.encryptChunk(testData, symmetricKey, hmacKey, 1);
        
        // First verification should pass
        boolean result1 = CryptoUtils.verifyIntegrity(message, hmacKey, transferId);
        LoggingManager.logSecurity(logger, "TEST: First verification result: " + result1);
        
        // Second verification of the same message should detect a duplicate
        boolean result2 = CryptoUtils.verifyIntegrity(message, hmacKey, transferId);
        LoggingManager.logSecurity(logger, "TEST: Second verification result: " + result2 + 
                                 " (should still pass but log duplicate notice)");
    }
    
    /**
     * Test sequence validation
     */
    private static void testSequenceValidation(SecretKey symmetricKey, SecretKey hmacKey) throws Exception {
        String transferId = UUID.randomUUID().toString();
        LoggingManager.logSecurity(logger, "TEST: Sequence validation - Transfer ID: " + transferId);
        
        // Create a series of chunks with sequential numbers
        List<SecureMessage> messages = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            byte[] testData = ("Test data for sequence " + i).getBytes();
            messages.add(CryptoUtils.encryptChunk(testData, symmetricKey, hmacKey, i));
        }
        
        // Verify in order
        LoggingManager.logSecurity(logger, "TEST: Verifying chunks in sequence...");
        for (int i = 0; i < messages.size(); i++) {
            boolean result = CryptoUtils.verifyIntegrity(messages.get(i), hmacKey, transferId);
            LoggingManager.logSecurity(logger, "TEST: Sequence " + i + " verification: " + result);
        }
        
        // Try out of order (should still work but log warnings)
        LoggingManager.logSecurity(logger, "TEST: Verifying chunks out of sequence...");
        String transferId2 = UUID.randomUUID().toString();
        
        // Create more test messages but verify in reverse order
        List<SecureMessage> messages2 = new ArrayList<>();
        for (int i = 10; i < 15; i++) {
            byte[] testData = ("Test data for out-of-sequence " + i).getBytes();
            messages2.add(CryptoUtils.encryptChunk(testData, symmetricKey, hmacKey, i));
        }
        
        // Verify in reverse order
        for (int i = messages2.size() - 1; i >= 0; i--) {
            boolean result = CryptoUtils.verifyIntegrity(messages2.get(i), hmacKey, transferId2);
            LoggingManager.logSecurity(logger, "TEST: Out-of-sequence " + (i + 10) + " verification: " + result);
        }
    }
    
    /**
     * Test transfer completion cleanup
     */
    private static void testTransferCompletion(SecretKey symmetricKey, SecretKey hmacKey) throws Exception {
        String transferId = UUID.randomUUID().toString();
        LoggingManager.logSecurity(logger, "TEST: Transfer completion - Transfer ID: " + transferId);
        
        // Create and verify a few chunks
        for (int i = 0; i < 3; i++) {
            byte[] testData = ("Test data for completion test " + i).getBytes();
            SecureMessage message = CryptoUtils.encryptChunk(testData, symmetricKey, hmacKey, i);
            CryptoUtils.verifyIntegrity(message, hmacKey, transferId);
        }
        
        // Mark transfer as complete
        CryptoUtils.markTransferComplete(transferId);
        LoggingManager.logSecurity(logger, "TEST: Marked transfer as complete: " + transferId);
        
        // Wait for cleanup to occur
        LoggingManager.logSecurity(logger, "TEST: Waiting for cleanup...");
        Thread.sleep(11000); // Wait 11 seconds (cleanup delay is 10 seconds)
        
        // Try to verify a new chunk with same transfer ID
        // This should work as if it's a new transfer
        byte[] newData = "Test data after completion".getBytes();
        SecureMessage newMessage = CryptoUtils.encryptChunk(newData, symmetricKey, hmacKey, 0);
        boolean result = CryptoUtils.verifyIntegrity(newMessage, hmacKey, transferId);
        
        LoggingManager.logSecurity(logger, "TEST: Verification after cleanup: " + result + 
                                 " (should pass as if new transfer)");
    }
    
    /**
     * Test replay attack simulation
     */
    private static void testReplayAttack(SecretKey symmetricKey, SecretKey hmacKey) throws Exception {
        String transferId = UUID.randomUUID().toString();
        LoggingManager.logSecurity(logger, "TEST: Replay attack simulation - Transfer ID: " + transferId);
        
        // Create legitimate messages
        List<SecureMessage> legitimateMessages = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            byte[] testData = ("Legitimate message " + i).getBytes();
            legitimateMessages.add(CryptoUtils.encryptChunk(testData, symmetricKey, hmacKey, i));
        }
        
        // Process legitimate messages
        for (int i = 0; i < legitimateMessages.size(); i++) {
            boolean result = CryptoUtils.verifyIntegrity(legitimateMessages.get(i), hmacKey, transferId);
            LoggingManager.logSecurity(logger, "TEST: Legitimate message " + i + " verification: " + result);
        }
        
        // Create a manually crafted replay attack (changing nonce but keeping sequence number)
        // This simulates an attacker trying to replay message 1 by modifying the nonce
        SecureMessage originalMessage = legitimateMessages.get(1); // Message with sequence 1
        
        // Create a fake replay message by manipulating the nonce
        // This mimics what an attacker might try to do
        SecureMessage replayMessage = new SecureMessage(
            originalMessage.encryptedData,
            originalMessage.mac,
            originalMessage.iv,
            System.currentTimeMillis(), // Current timestamp
            generateFakeNonce() + ":1" // Keep sequence number 1 but change base nonce
        );
        
        // Try to verify the replay message - should be detected and rejected
        boolean replayResult = CryptoUtils.verifyIntegrity(replayMessage, hmacKey, transferId);
        LoggingManager.logSecurity(logger, "TEST: Replay attack detection test result: " + replayResult + 
                                 " (should be rejected - false)");
    }
    
    /**
     * Generate a test crypto key
     */
    private static SecretKey generateTestKey(String algorithm) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm.split("SHA")[0]); // Handle HMAC algorithms
        if (algorithm.equals("AES")) {
            keyGen.init(256);
        }
        return keyGen.generateKey();
    }
    
    /**
     * Generate a fake nonce for replay testing
     */
    private static String generateFakeNonce() throws NoSuchAlgorithmException {
        byte[] nonceBytes = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(nonceBytes);
        
        StringBuilder sb = new StringBuilder();
        for (byte b : nonceBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
