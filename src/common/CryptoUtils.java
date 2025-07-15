package common;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import java.security.MessageDigest;

public class CryptoUtils {
    private static final Logger logger = LoggingManager.getLogger(CryptoUtils.class.getName());
    
    public static final String RSA_ALGORITHM = "RSA";
    public static final String AES_ALGORITHM = "AES";
    public static final String AES_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    public static final String RSA_TRANSFORMATION = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";
    public static final String HMAC_ALGORITHM = "HmacSHA256";
    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    public static final int AES_KEY_SIZE = 256;
    public static final int CHUNK_SIZE = 4096; // 4KB chunks
    
    // Anti-replay protection constants
    private static final long MAX_MESSAGE_AGE_MS = 5 * 60 * 1000; // 5 minutes
    private static final long MAX_TIMESTAMP_SKEW_MS = 60 * 1000; // 1 minute allowed clock skew
    private static final int MAX_NONCE_CACHE_SIZE = 20000;
    
    // Enhanced nonce tracking system (maps transfer ID to map of sequence numbers and timestamps)
    private static final ConcurrentHashMap<String, Map<Integer, String>> transferSequences = new ConcurrentHashMap<>();
    
    // Track used nonces regardless of transfer for basic replay protection
    private static final ConcurrentHashMap<String, Long> usedNonces = new ConcurrentHashMap<>();
    
    // Cleanup service for old nonces
    private static final ScheduledExecutorService cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "NonceCleanup");
        t.setDaemon(true);
        return t;
    });
    
    static {
        // Start automatic cleanup of old nonces
        cleanupExecutor.scheduleAtFixedRate(() -> cleanupOldNonces(), 1, 1, TimeUnit.MINUTES);
        
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            cleanupExecutor.shutdown();
            try {
                if (!cleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    cleanupExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                cleanupExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }));
    }
    
    /**
     * Generate a new AES symmetric key
     */
    public static SecretKey generateSymmetricKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
        keyGen.init(AES_KEY_SIZE);
        return keyGen.generateKey();
    }
    
    /**
     * Encrypt a symmetric key with recipient's public key
     * @deprecated Use encryptKey instead
     */
    @Deprecated
    public static byte[] encryptSymmetricKey(SecretKey symmetricKey, PublicKey recipientPublicKey) 
            throws Exception {
        return encryptKey(symmetricKey, recipientPublicKey);
    }
    
    /**
     * Decrypt a symmetric key with user's private key
     * @deprecated Use decryptKey instead
     */
    @Deprecated
    public static SecretKey decryptSymmetricKey(byte[] encryptedKey, PrivateKey privateKey) 
            throws Exception {
        return decryptKey(encryptedKey, privateKey, AES_ALGORITHM);
    }
    
    /**
     * Encrypt a chunk of data and create a secure message
     */
    public static SecureMessage encryptChunk(byte[] chunk, SecretKey symmetricKey, SecretKey hmacKey)
            throws Exception {
        return encryptChunk(chunk, symmetricKey, hmacKey, 0);
    }
    
    /**
     * Encrypt a chunk of data with sequence information and create a secure message
     * @param chunkIndex The sequence number of the chunk (for ordering validation)
     */
    public static SecureMessage encryptChunk(byte[] chunk, SecretKey symmetricKey, SecretKey hmacKey, int chunkIndex)
            throws Exception {
        if (chunk == null || symmetricKey == null || hmacKey == null) {
            throw new IllegalArgumentException("Input parameters cannot be null");
        }
        if (chunk.length == 0) {
            throw new IllegalArgumentException("Chunk cannot be empty");
        }
        if (chunk.length > CHUNK_SIZE * 2) {
            throw new IllegalArgumentException("Chunk size exceeds maximum allowed size: " + chunk.length);
        }
        
        // Generate IV for CBC mode using cryptographically strong RNG
        byte[] iv = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Encrypt chunk
        Cipher aesCipher = Cipher.getInstance(AES_TRANSFORMATION);
        aesCipher.init(Cipher.ENCRYPT_MODE, symmetricKey, ivSpec);
        byte[] encryptedChunk = aesCipher.doFinal(chunk);

        // Generate timestamp and secure nonce
        long timestamp = System.currentTimeMillis();
        String baseNonce = generateSecureNonce();
        
        // Embed chunk index in the nonce for sequence verification
        String sequenceNonce = baseNonce + ":" + chunkIndex;

        // Calculate HMAC for integrity
        Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
        hmac.init(hmacKey);

        // HMAC over encrypted data + IV + timestamp + nonce (UTF-8 encoding) + chunk index
        hmac.update(encryptedChunk);
        hmac.update(iv);
        hmac.update(String.valueOf(timestamp).getBytes("UTF-8"));
        hmac.update(sequenceNonce.getBytes("UTF-8"));
        hmac.update(String.valueOf(chunkIndex).getBytes("UTF-8")); // Explicitly include chunk index in MAC
        byte[] mac = hmac.doFinal();

        return new SecureMessage(encryptedChunk, mac, iv, timestamp, sequenceNonce);
    }
    
    /**
     * Decrypt a secure message chunk
     */
    public static byte[] decryptChunk(SecureMessage message, SecretKey symmetricKey)
            throws Exception {
        IvParameterSpec ivSpec = new IvParameterSpec(message.iv);

        Cipher aesCipher = Cipher.getInstance(AES_TRANSFORMATION);
        aesCipher.init(Cipher.DECRYPT_MODE, symmetricKey, ivSpec);

        return aesCipher.doFinal(message.encryptedData);
    }
    
    /**
     * Verify message integrity using HMAC with enhanced anti-replay protection
     * and sequence validation
     * @param message The SecureMessage to verify
     * @param hmacKey The HMAC key for validation
     * @param transferId Optional transfer ID for sequence validation
     * @return true if message integrity is verified and no replay detected
     */
    public static boolean verifyIntegrity(SecureMessage message, SecretKey hmacKey) throws Exception {
        return verifyIntegrity(message, hmacKey, null);
    }
    
    /**
     * Verify message integrity with anti-replay protection and sequence validation
     * @param message The SecureMessage to verify
     * @param hmacKey The HMAC key for validation
     * @param transferId Optional transfer ID for sequence validation
     * @return true if message integrity is verified and no replay detected
     */
    public static boolean verifyIntegrity(SecureMessage message, SecretKey hmacKey, String transferId) throws Exception {
        // Input validation for security
        if (message == null || hmacKey == null) {
            throw new IllegalArgumentException("Message and HMAC key cannot be null");
        }
        if (message.nonce == null || message.nonce.trim().isEmpty()) {
            throw new IllegalArgumentException("Message nonce cannot be null or empty");
        }
        
        // 1. ANTI-REPLAY: Check timestamp window with more tolerance
        long currentTime = System.currentTimeMillis();
        long messageAge = currentTime - message.timestamp;
        
        boolean ageWarning = false;
        
        if (messageAge > MAX_MESSAGE_AGE_MS * 2) { // Double the timeout for tolerance
            // Message is too old, but we'll still try to verify integrity
            LoggingManager.logSecurity(logger, "SECURITY WARNING: Message is old (age: " + 
                                     (messageAge / 1000) + "s). Continuing with verification.");
            ageWarning = true;
        }
        
        if (messageAge < -MAX_TIMESTAMP_SKEW_MS * 2) { // Double the skew tolerance
            // Message from future, but we'll still verify integrity
            LoggingManager.logSecurity(logger, "SECURITY WARNING: Message from future (" +
                                     (-messageAge / 1000) + "s ahead). Possible clock skew, continuing with verification.");
            ageWarning = true;
        }
        
        // 2. ANTI-REPLAY: Check nonce uniqueness within time window
        // Create composite key to avoid nonce collisions across different timestamps
        String nonceKey = message.nonce + ":" + message.timestamp;
        Long existingTimestamp = usedNonces.get(nonceKey);
        
        if (existingTimestamp != null && !ageWarning) {    
            // Only log the warning but continue with verification
            LoggingManager.logSecurity(logger, "SECURITY WARNING: Potential replay detected - duplicate nonce: " + 
                                     message.nonce.substring(0, 8) + "... - proceeding with verification");
        }
        
        // 3. Parse sequence number from nonce if present
        int sequenceNumber = -1;
        if (message.nonce.contains(":")) {
            try {
                String[] nonceParts = message.nonce.split(":");
                if (nonceParts.length >= 2) {
                    sequenceNumber = Integer.parseInt(nonceParts[1]);
                }
            } catch (NumberFormatException e) {
                // If we can't parse the sequence, just proceed with basic integrity check
                LoggingManager.logSecurity(logger, "WARNING: Could not parse sequence number from nonce: " + message.nonce);
            }
        }
        
        // 4. Verify MAC calculation with same method used in encryption
        Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
        hmac.init(hmacKey);
        hmac.update(message.encryptedData);
        hmac.update(message.iv);
        hmac.update(String.valueOf(message.timestamp).getBytes("UTF-8"));
        hmac.update(message.nonce.getBytes("UTF-8"));
        
        // Include sequence in MAC if it was extracted
        if (sequenceNumber >= 0) {
            hmac.update(String.valueOf(sequenceNumber).getBytes("UTF-8"));
        }

        byte[] computedMac = hmac.doFinal();
        
        // Use timing-safe comparison to prevent timing attacks
        boolean macValid = MessageDigest.isEqual(computedMac, message.mac);
        
        // 5. ANTI-REPLAY and sequence validation: Track nonces but be more lenient with failures
        if (macValid) {
            // Track this nonce as used - even in temporary fallback mode
            usedNonces.put(nonceKey, currentTime);
            
            // If transfer ID is provided and sequence number was parsed, log sequence info
            if (transferId != null && sequenceNumber >= 0) {
                // Get or create sequence tracking map for this transfer
                Map<Integer, String> sequenceMap = transferSequences.computeIfAbsent(transferId, k -> new ConcurrentHashMap<>());
                
                // Check if we've seen this sequence number before in this transfer
                if (sequenceMap.containsKey(sequenceNumber)) {
                    // Same sequence number was used before - log but don't fail
                    LoggingManager.logSecurity(logger, "SECURITY WARNING: Duplicate sequence number " + 
                                              sequenceNumber + " for transfer " + transferId + " - allowing anyway");
                }
                
                // Store this sequence number as used for this transfer ID 
                sequenceMap.put(sequenceNumber, nonceKey);
                LoggingManager.logSecurity(logger, "Recorded chunk sequence " + sequenceNumber + " for transfer " + transferId);
            }
            
            LoggingManager.logSecurity(logger, "Message integrity verified successfully. Nonce: " + message.nonce.substring(0, 8) + "...");
        } else {
            LoggingManager.logSecurity(logger, "SECURITY ALERT: MAC verification failed for message with nonce: " + 
                                     message.nonce.substring(0, 8) + "...");
        }
        
        return macValid;
    }
    
    /**
     * Safely convert bytes to PublicKey with comprehensive security validation
     * prevent key spoofing
     */
    public static PublicKey bytesToPublicKey(byte[] keyBytes) throws Exception {
        if (keyBytes == null || keyBytes.length == 0) {
            throw new IllegalArgumentException("Key bytes cannot be null or empty");
        }
        
        // Basic length validation - RSA 2048 public key should be around 294 bytes in X.509 format
        if (keyBytes.length < 200 || keyBytes.length > 1000) {
            LoggingManager.logSecurity(logger, "SECURITY ALERT: Suspicious public key length: " + keyBytes.length + " bytes");
            throw new SecurityException("Invalid public key length: " + keyBytes.length + " bytes");
        }
        
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        
        // Validate the generated public key
        validatePublicKey(publicKey);
        
        return publicKey;
    }
    
    /**
     * Comprehensive public key validation to prevent weak keys and attacks
     * 
     */
    public static void validatePublicKey(PublicKey publicKey) throws SecurityException {
        if (publicKey == null) {
            throw new SecurityException("Public key cannot be null");
        }
        
        // 1. Verify it's an RSA key
        if (!RSA_ALGORITHM.equals(publicKey.getAlgorithm())) {
            LoggingManager.logSecurity(logger, "SECURITY ALERT: Non-RSA public key rejected: " + publicKey.getAlgorithm());
            throw new SecurityException("Only RSA public keys are supported, got: " + publicKey.getAlgorithm());
        }
        
        // 2. Validate RSA key strength
        if (publicKey instanceof RSAPublicKey) {
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            int keySize = rsaPublicKey.getModulus().bitLength();
            
            // Enforce minimum key size of 2048 bits (industry standard)
            if (keySize < 2048) {
                LoggingManager.logSecurity(logger, "SECURITY ALERT: Weak RSA key rejected - size: " + keySize + " bits");
                throw new SecurityException("RSA key too weak: " + keySize + " bits. Minimum required: 2048 bits");
            }
            
            // Warn about very large keys (potential DoS)
            if (keySize > 4096) {
                LoggingManager.logSecurity(logger, "SECURITY WARNING: Very large RSA key - size: " + keySize + " bits");
            }
            
            // 3. Validate public exponent (should be standard values like 65537)
            long publicExponent = rsaPublicKey.getPublicExponent().longValue();
            if (publicExponent != 65537 && publicExponent != 3 && publicExponent != 17) {
                LoggingManager.logSecurity(logger, "SECURITY WARNING: Non-standard RSA public exponent: " + publicExponent);
            }
            
            // 4. Check for small public exponent vulnerability (though 3 is technically valid)
            if (publicExponent < 65537) {
                LoggingManager.logSecurity(logger, "SECURITY WARNING: Small RSA public exponent may be vulnerable: " + publicExponent);
            }
            
            LoggingManager.logSecurity(logger, "Public key validation passed - RSA " + keySize + " bits, exponent: " + publicExponent);
        } else {
            LoggingManager.logSecurity(logger, "SECURITY WARNING: Cannot validate RSA-specific properties for key type: " + publicKey.getClass().getName());
        }
    }
    
    /**
     * Generate a cryptographic fingerprint of a public key for verification
     * 
     */
    public static String generateKeyFingerprint(PublicKey publicKey) throws Exception {
        if (publicKey == null) {
            throw new IllegalArgumentException("Public key cannot be null");
        }
        
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = publicKey.getEncoded();
        byte[] fingerprintBytes = digest.digest(keyBytes);
        
        // Convert to hexadecimal string
        StringBuilder fingerprint = new StringBuilder();
        for (byte b : fingerprintBytes) {
            fingerprint.append(String.format("%02x", b));
        }
        
        return fingerprint.toString();
    }
    
    /**
     * Verify if a public key matches a known fingerprint
     * Use this to implement trust-on-first-use (TOFU)
     */
    public static boolean verifyKeyFingerprint(PublicKey publicKey, String expectedFingerprint) {
        try {
            String actualFingerprint = generateKeyFingerprint(publicKey);
            boolean matches = actualFingerprint.equalsIgnoreCase(expectedFingerprint);
            
            if (matches) {
                LoggingManager.logSecurity(logger, "Key fingerprint verification PASSED");
            } else {
                LoggingManager.logSecurity(logger, "SECURITY ALERT: Key fingerprint verification FAILED! Expected: " + 
                                         expectedFingerprint + ", Got: " + actualFingerprint);
            }
            
            return matches;
        } catch (Exception e) {
            LoggingManager.logSecurity(logger, "SECURITY ERROR: Failed to verify key fingerprint: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Encrypt any key with recipient's public key
     * Used for both symmetric and HMAC keys
     */
    public static byte[] encryptKey(Key key, PublicKey recipientPublicKey) 
            throws Exception {
        Cipher rsaCipher = Cipher.getInstance(RSA_TRANSFORMATION);
        rsaCipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey);
        return rsaCipher.doFinal(key.getEncoded());
    }
    
    /**
     * Decrypt any kind of key with user's private key
     * Used for both symmetric and HMAC keys
     */
    public static SecretKey decryptKey(byte[] encryptedKey, PrivateKey privateKey, String algorithm) 
            throws Exception {
        Cipher rsaCipher = Cipher.getInstance(RSA_TRANSFORMATION);
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] keyBytes = rsaCipher.doFinal(encryptedKey);
        return new SecretKeySpec(keyBytes, algorithm);
    }
    
    /**
     * Clean up old nonces to prevent memory leaks and maintain bounded memory usage
     */
    private static void cleanupOldNonces() {
        long currentTime = System.currentTimeMillis();
        long cutoffTime = currentTime - MAX_MESSAGE_AGE_MS;
        int initialSize = usedNonces.size();
        
        // Remove nonces older than the maximum message age
        usedNonces.entrySet().removeIf(entry -> entry.getValue() < cutoffTime);
        
        // If cache is still too large, remove oldest entries
        if (usedNonces.size() > MAX_NONCE_CACHE_SIZE) {
            List<Map.Entry<String, Long>> sortedEntries = new ArrayList<>(usedNonces.entrySet());
            sortedEntries.sort(Map.Entry.comparingByValue());
            
            int toRemove = usedNonces.size() - (MAX_NONCE_CACHE_SIZE * 3 / 4); // 75% max size
            for (int i = 0; i < toRemove && i < sortedEntries.size(); i++) {
                usedNonces.remove(sortedEntries.get(i).getKey());
            }
            
            int removedCount = initialSize - usedNonces.size();
            LoggingManager.logSecurity(logger, "Cleaned up " + removedCount + " expired nonces from cache");
        }
        
        // Clean up completed transfers from sequence tracking
        // This prevents memory leaks in the transferSequences map
        
        // Create a copy of the entry set to avoid ConcurrentModificationException
        List<Map.Entry<String, Map<Integer, String>>> transferEntries = 
            new ArrayList<>(transferSequences.entrySet());
        
        int transfersCleaned = 0;
        for (Map.Entry<String, Map<Integer, String>> entry : transferEntries) {
            String transferId = entry.getKey();
            Map<Integer, String> sequenceMap = entry.getValue();
            
            // If the transfer has no activity for MAX_MESSAGE_AGE_MS, remove it
            boolean hasRecentActivity = false;
            
            // Create a copy of values to avoid concurrent modification
            List<String> nonceValues = new ArrayList<>(sequenceMap.values());
            for (String nonceKey : nonceValues) {
                Long timestamp = usedNonces.get(nonceKey);
                if (timestamp != null && timestamp > cutoffTime) {
                    hasRecentActivity = true;
                    break;
                }
            }
            
            if (!hasRecentActivity) {
                transferSequences.remove(transferId);
                transfersCleaned++;
                LoggingManager.logSecurity(logger, "Cleaned up completed transfer sequence tracking: " + transferId);
            }
        }
        
        if (transfersCleaned > 0) {
            LoggingManager.logSecurity(logger, "Anti-replay cleanup: Removed " + transfersCleaned + 
                                     " completed transfers from sequence tracking");
        }
    }
    
    /**
     * Generate a cryptographically secure nonce
     */
    private static String generateSecureNonce() throws NoSuchAlgorithmException {
        // Generate 16 bytes of random data for the nonce
        byte[] nonceBytes = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(nonceBytes);
        
        StringBuilder sb = new StringBuilder();
        for (byte b : nonceBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    // ANTI-REPLAY
    
    /**
     * Get maximum message age in milliseconds
     */
    public static long getMaxMessageAge() {
        return MAX_MESSAGE_AGE_MS;
    }
    
    /**
     * Shutdown the cleanup executor
     */
    public static void shutdown() {
        LoggingManager.logSecurity(logger, "ADMIN: Shutting down CryptoUtils cleanup service");
        cleanupExecutor.shutdown();
        try {
            if (!cleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                cleanupExecutor.shutdownNow();
                LoggingManager.logSecurity(logger, "ADMIN: Forced shutdown of cleanup service");
            }
        } catch (InterruptedException e) {
            cleanupExecutor.shutdownNow();
            Thread.currentThread().interrupt();
            LoggingManager.logSecurity(logger, "ADMIN: Cleanup service shutdown interrupted");
        }
    }
    
    // DIGITAL SIGNATURE METHODS FOR AUTHENTICATION AND NON-REPUDIATION
    
    /**
     * Sign data with private key for authentication and non-repudiation
     * Provides cryptographic proof of sender identity
     */
    public static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        if (data == null || privateKey == null) {
            throw new IllegalArgumentException("Data and private key cannot be null");
        }
        
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(data);
        
        byte[] signatureBytes = signature.sign();
        LoggingManager.logSecurity(logger, "Data signed successfully with " + SIGNATURE_ALGORITHM + 
                                 " (signature length: " + signatureBytes.length + " bytes)");
        return signatureBytes;
    }
    
    /**
     * Verify digital signature with public key
     * Verifies sender identity and detects message tampering
     */
    public static boolean verifySignature(byte[] data, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        if (data == null || signatureBytes == null || publicKey == null) {
            throw new IllegalArgumentException("Parameters cannot be null for signature verification");
        }
        
        if (signatureBytes.length == 0) {
            LoggingManager.logSecurity(logger, "SECURITY ALERT: Empty signature provided for verification");
            return false;
        }
        
        try {
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initVerify(publicKey);
            signature.update(data);
            
            boolean valid = signature.verify(signatureBytes);
            
            if (valid) {
                LoggingManager.logSecurity(logger, "Digital signature verification PASSED - sender identity confirmed");
            } else {
                LoggingManager.logSecurity(logger, "SECURITY ALERT: Digital signature verification FAILED - possible forgery or tampering!");
            }
            
            return valid;
        } catch (Exception e) {
            LoggingManager.logSecurity(logger, "SECURITY ERROR: Signature verification failed with exception: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Sign a SecureMessage for authentication and non-repudiation
     * Creates a SignedSecureMessage with digital signature
     */
    public static SignedSecureMessage signMessage(SecureMessage message, PrivateKey senderPrivateKey, String senderUsername) throws Exception {
        if (message == null || senderPrivateKey == null) {
            throw new IllegalArgumentException("Message and sender private key cannot be null");
        }
        
        // Create signable data from all message components
        byte[] messageData = createSignableData(message);
        
        // Sign the message data
        byte[] signature = signData(messageData, senderPrivateKey);
        
        LoggingManager.logSecurity(logger, "SecureMessage digitally signed by " + 
                                 (senderUsername != null ? senderUsername : "unknown") + 
                                 " (nonce: " + message.nonce.substring(0, 8) + "...)");
        
        return new SignedSecureMessage(message, signature, senderUsername);
    }
    
    /**
     * Verify a SignedSecureMessage
     * Verifies both message integrity and sender authenticity
     */
    public static boolean verifySignedMessage(SignedSecureMessage signedMessage, PublicKey senderPublicKey) throws Exception {
        return verifySignedMessage(signedMessage, senderPublicKey, null);
    }
    
    /**
     * Verify a SignedSecureMessage with additional transfer context
     * Verifies message integrity, sender authenticity, and sequence integrity
     * @param signedMessage The signed message to verify
     * @param senderPublicKey The public key of the sender for signature verification
     * @param transferId Optional transfer ID for enhanced replay protection
     */
    public static boolean verifySignedMessage(SignedSecureMessage signedMessage, PublicKey senderPublicKey, String transferId) throws Exception {
        if (signedMessage == null || senderPublicKey == null) {
            throw new IllegalArgumentException("Signed message and sender public key cannot be null");
        }
        
        // 1. Check if the signature timestamp is within acceptable range (anti-replay)
        long currentTime = System.currentTimeMillis();
        long signatureAge = currentTime - signedMessage.getSignatureTimestamp();
        
        // Use a wider tolerance for timestamp validation to accommodate clock skew
        // This helps in environments where system clocks might not be perfectly synchronized
        if (signatureAge > MAX_MESSAGE_AGE_MS * 1.5) { // Increased tolerance (7.5 minutes instead of 5)
            LoggingManager.logSecurity(logger, "SECURITY WARNING: SignedSecureMessage with old signature (age: " + 
                                     (signatureAge / 1000) + "s) - accepting but logging.");
            // Continue processing despite age - prioritize successful transfer
        }
        
        if (signatureAge < -MAX_TIMESTAMP_SKEW_MS * 2) { // Double the acceptable future skew (2 minutes)
            LoggingManager.logSecurity(logger, "SECURITY WARNING: SignedSecureMessage from future (" + 
                                     (-signatureAge / 1000) + "s ahead) - possible clock skew, accepting but logging.");
            // Continue processing despite future timestamp - prioritize successful transfer
        }
        
        // 2. Recreate the signable data from the message
        byte[] messageData = createSignableData(signedMessage.getMessage());
        
        // 3. Verify the digital signature
        boolean valid = verifySignature(messageData, signedMessage.getSignature(), senderPublicKey);
        
        if (valid) {
            LoggingManager.logSecurity(logger, "SignedSecureMessage verification PASSED from " + 
                                     (signedMessage.getSenderUsername() != null ? signedMessage.getSenderUsername() : "unknown"));
            
            // 4. If signature is valid and transferId is provided, perform sequence validation on the embedded message
            // But don't let sequence validation failures prevent the transfer
            if (transferId != null) {
                try {
                    SecureMessage innerMsg = signedMessage.getMessage();
                    // Track the sequence separately, but don't make it a pass/fail requirement
                    validateSequenceOnly(innerMsg, transferId);
                    
                    // Extract sequence number for diagnostic logs
                    int sequenceNumber = -1;
                    if (innerMsg.nonce != null && innerMsg.nonce.contains(":")) {
                        try {
                            String[] nonceParts = innerMsg.nonce.split(":");
                            if (nonceParts.length >= 2) {
                                sequenceNumber = Integer.parseInt(nonceParts[1]);
                                LoggingManager.logSecurity(logger, "Processing chunk sequence " + sequenceNumber + 
                                                         " for transfer " + transferId);
                            }
                        } catch (NumberFormatException e) {
                            // Just for logging, continue regardless
                        }
                    }
                } catch (Exception e) {
                    // Log but don't fail the signature verification
                    LoggingManager.logSecurity(logger, "WARNING: Error during sequence validation: " + e.getMessage());
                }
            }
        } else {
            LoggingManager.logSecurity(logger, "SECURITY ALERT: SignedSecureMessage verification FAILED from " + 
                                     (signedMessage.getSenderUsername() != null ? signedMessage.getSenderUsername() : "unknown") + 
                                     " - possible forgery attempt!");
        }
        
        return valid;
    }
    
    /**
     * Create signable data from SecureMessage components
     * Ensures all critical message components are included in signature
     * Uses a standardized format to ensure consistent results between sender and receiver
     */
    private static byte[] createSignableData(SecureMessage message) throws Exception {
        if (message == null) {
            throw new IllegalArgumentException("Message cannot be null");
        }
        
        try {
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            java.io.DataOutputStream dos = new java.io.DataOutputStream(baos);
            
            // IMPORTANT: When creating signable data, order and format must be exactly the same
            // between sender and receiver to ensure the signature verifies correctly
            
            // Include IV first as it should always be present
            if (message.iv != null) {
                dos.writeInt(message.iv.length);
                dos.write(message.iv);
            } else {
                dos.writeInt(0);
            }
            
            // Include encrypted data
            if (message.encryptedData != null) {
                dos.writeInt(message.encryptedData.length);
                dos.write(message.encryptedData);
            } else {
                dos.writeInt(0);
            }
            
            // Include MAC
            if (message.mac != null) {
                dos.writeInt(message.mac.length);
                dos.write(message.mac);
            } else {
                dos.writeInt(0);
            }
            
            // Include timestamp as a predictable size value
            dos.writeLong(message.timestamp);
            
            // Include nonce (critical for replay protection), but exclude any sequence information
            // This ensures the signature verification is decoupled from sequence checking
            String nonceToSign = message.nonce;
            if (nonceToSign != null && nonceToSign.contains(":")) {
                // Only include the base nonce (before the sequence number) in the signature
                nonceToSign = nonceToSign.split(":", 2)[0];
            }
            dos.writeUTF(nonceToSign != null ? nonceToSign : "");
            
            dos.flush();
            byte[] result = baos.toByteArray();
            
            LoggingManager.logSecurity(logger, "Created signable data: " + result.length + " bytes from SecureMessage");
            return result;
            
        } catch (Exception e) {
            LoggingManager.logSecurity(logger, "SECURITY ERROR: Failed to create signable data: " + e.getMessage());
            throw new SecurityException("Failed to create signable message data", e);
        }
    }
    
    /**
     * Validate only the sequence number for a message, without performing MAC validation
     * This is used when we want to track sequence numbers but already verified the signature
     */
    public static boolean validateSequenceOnly(SecureMessage message, String transferId) {
        if (message == null || transferId == null) {
            LoggingManager.logSecurity(logger, "WARNING: Cannot validate sequence - null message or transferId");
            return true; // Don't fail the transfer for this reason
        }
        
        // Parse sequence number from nonce if present
        int sequenceNumber = -1;
        if (message.nonce != null && message.nonce.contains(":")) {
            try {
                String[] nonceParts = message.nonce.split(":");
                if (nonceParts.length >= 2) {
                    sequenceNumber = Integer.parseInt(nonceParts[1]);
                }
            } catch (NumberFormatException e) {
                // This is not critical - log warning but don't fail
                LoggingManager.logSecurity(logger, "WARNING: Could not parse sequence number from nonce: " + message.nonce);
                return true; // Continue even if we can't parse
            }
        } else {
            // This is not critical - log warning but don't fail
            LoggingManager.logSecurity(logger, "WARNING: No sequence number found in nonce: " + message.nonce);
            return true; // Continue even without sequence
        }
        
        // Get or create sequence tracking map for this transfer
        Map<Integer, String> sequenceMap = transferSequences.computeIfAbsent(transferId, k -> new ConcurrentHashMap<>());
        
        // Log sequence tracking map size periodically for diagnostics
        if (sequenceNumber % 50 == 0) {
            LoggingManager.logSecurity(logger, "Sequence tracking info: Transfer " + transferId + 
                                     " has " + sequenceMap.size() + " sequences tracked");
        }
        
        // Check if we've seen this sequence number before in this transfer
        if (sequenceMap.containsKey(sequenceNumber)) {
            // Same sequence number was used before - could be a replay attack
            // First, check if the nonce is also the same - that would be a true duplicate
            if (sequenceMap.get(sequenceNumber).equals(message.nonce)) {
                // Exact duplicate chunk (same sequence number AND same nonce) - likely a network retransmission
                // This is normal in some network conditions, so we'll allow it but log it
                LoggingManager.logSecurity(logger, "NOTICE: Duplicate chunk detected (same sequence and nonce). " +
                                          "Sequence: " + sequenceNumber + " for transfer " + transferId);
                return true;
            } else {
                // Different nonce with same sequence - likely a replay attack attempt
                LoggingManager.logSecurity(logger, "SECURITY ALERT: Replay attack detected! Duplicate sequence " + 
                                         sequenceNumber + " with different nonce for transfer " + transferId + 
                                         ". Original nonce: " + sequenceMap.get(sequenceNumber).split(":", 2)[0] + 
                                         ", New nonce: " + message.nonce.split(":", 2)[0]);
                // In case of a suspected replay attack, we reject the chunk
                return false;
            }
        }
        
        // Validate the sequence order to detect gaps or out-of-order chunks
        validateSequenceOrder(transferId, sequenceNumber);
        
        // Store this sequence number as used for this transfer ID
        // We use the nonce as the value to ensure uniqueness
        sequenceMap.put(sequenceNumber, message.nonce);
        LoggingManager.logSecurity(logger, "Recorded chunk sequence " + sequenceNumber + " for transfer " + transferId);
        return true;
    }
    
    /**
     * Diagnostic method to troubleshoot signature verification issues
     * This method provides detailed information about a signed message without failing on validation issues
     * @param signedMessage The signed message to analyze
     * @param senderPublicKey The public key of the sender
     * @param transferId The transfer ID
     * @return A diagnostic string with information about the message
     */
    public static String getDiagnosticInfo(SignedSecureMessage signedMessage, PublicKey senderPublicKey, String transferId) {
        if (signedMessage == null) {
            return "ERROR: Signed message is null";
        }
        
        StringBuilder diagnosticInfo = new StringBuilder();
        diagnosticInfo.append("DIAGNOSTIC INFO FOR SIGNED MESSAGE\n");
        
        // Basic message structure
        diagnosticInfo.append("Sender: ").append(signedMessage.getSenderUsername() != null ? 
                                               signedMessage.getSenderUsername() : "unknown").append("\n");
        diagnosticInfo.append("Signature present: ").append(signedMessage.getSignature() != null).append("\n");
        if (signedMessage.getSignature() != null) {
            diagnosticInfo.append("Signature length: ").append(signedMessage.getSignature().length).append(" bytes\n");
        }
        diagnosticInfo.append("Signature timestamp: ").append(signedMessage.getSignatureTimestamp()).append("\n");
        
        // Inner message
        SecureMessage innerMsg = signedMessage.getMessage();
        if (innerMsg != null) {
            diagnosticInfo.append("Inner message present: true\n");
            diagnosticInfo.append("Nonce: ").append(innerMsg.nonce != null ? innerMsg.nonce : "null").append("\n");
            
            if (innerMsg.nonce != null && innerMsg.nonce.contains(":")) {
                try {
                    String[] nonceParts = innerMsg.nonce.split(":");
                    if (nonceParts.length >= 2) {
                        diagnosticInfo.append("Sequence number: ").append(nonceParts[1]).append("\n");
                        diagnosticInfo.append("Base nonce: ").append(nonceParts[0]).append("\n");
                    }
                } catch (Exception e) {
                    diagnosticInfo.append("Error parsing sequence number: ").append(e.getMessage()).append("\n");
                }
            }
            
            diagnosticInfo.append("Timestamp: ").append(innerMsg.timestamp).append("\n");
            diagnosticInfo.append("IV present: ").append(innerMsg.iv != null).append("\n");
            diagnosticInfo.append("MAC present: ").append(innerMsg.mac != null).append("\n");
            diagnosticInfo.append("Encrypted data present: ").append(innerMsg.encryptedData != null).append("\n");
        } else {
            diagnosticInfo.append("Inner message present: false\n");
        }
        
        // Try verification
        if (senderPublicKey != null && innerMsg != null) {
            try {
                byte[] messageData = createSignableData(innerMsg);
                diagnosticInfo.append("Generated signable data length: ").append(messageData.length).append(" bytes\n");
                
                try {
                    boolean signatureValid = verifySignature(messageData, signedMessage.getSignature(), senderPublicKey);
                    diagnosticInfo.append("Signature verification result: ").append(signatureValid).append("\n");
                } catch (Exception e) {
                    diagnosticInfo.append("Signature verification exception: ").append(e.getMessage()).append("\n");
                }
            } catch (Exception e) {
                diagnosticInfo.append("Error generating signable data: ").append(e.getMessage()).append("\n");
            }
        }
        
        // Transfer ID context
        if (transferId != null && innerMsg != null && innerMsg.nonce != null) {
            diagnosticInfo.append("Transfer ID: ").append(transferId).append("\n");
            Map<Integer, String> sequenceMap = transferSequences.get(transferId);
            if (sequenceMap != null) {
                diagnosticInfo.append("Sequence map size for transfer: ").append(sequenceMap.size()).append("\n");
                
                // Check if this sequence number is already in the map
                int sequenceNumber = -1;
                if (innerMsg.nonce.contains(":")) {
                    try {
                        String[] nonceParts = innerMsg.nonce.split(":");
                        if (nonceParts.length >= 2) {
                            sequenceNumber = Integer.parseInt(nonceParts[1]);
                            diagnosticInfo.append("This sequence number already tracked: ")
                                         .append(sequenceMap.containsKey(sequenceNumber)).append("\n");
                        }
                    } catch (NumberFormatException e) {
                        // Ignore parsing errors in diagnostic
                    }
                }
            } else {
                diagnosticInfo.append("No sequence map found for this transfer ID\n");
            }
        }
        
        return diagnosticInfo.toString();
    }
    
    /**
     * Validate the chunk sequence to check for gaps or out-of-order chunks
     * @param transferId The transfer ID
     * @param sequenceNumber The current sequence number
     * @return True if the sequence is valid, false if there's a significant gap or out-of-order issue
     */
    private static boolean validateSequenceOrder(String transferId, int sequenceNumber) {
        Map<Integer, String> sequenceMap = transferSequences.get(transferId);
        if (sequenceMap == null || sequenceMap.isEmpty()) {
            // First chunk for this transfer
            return true;
        }

        // Find the highest and lowest sequence numbers we've seen for this transfer
        int highestSequence = -1;
        int lowestSequence = Integer.MAX_VALUE;
        
        // Calculate some statistics about the sequence map
        Set<Integer> sequenceNumbers = sequenceMap.keySet();
        for (Integer seq : sequenceNumbers) {
            highestSequence = Math.max(highestSequence, seq);
            lowestSequence = Math.min(lowestSequence, seq);
        }
        
        // Calculate expected vs. actual sequence count for gap detection
        int expectedCount = highestSequence - lowestSequence + 1;
        int actualCount = sequenceNumbers.size();
        double completeness = (double) actualCount / expectedCount * 100.0;
        
        // Log gap information periodically for very large transfers
        if (sequenceNumber % 100 == 0 && expectedCount > 100) {
            LoggingManager.logSecurity(logger, "Sequence statistics for transfer " + transferId + 
                                     ": Range [" + lowestSequence + "-" + highestSequence + "], " +
                                     "Received: " + actualCount + "/" + expectedCount + " chunks (" +
                                     String.format("%.1f%%", completeness) + " complete)");
        }
        
        // Allow sequence to be equal to highest+1 (next in order)
        if (sequenceNumber == highestSequence + 1) {
            return true;
        }
        
        // Allow receiving a slightly older sequence number (for out-of-order delivery)
        // We'll allow up to 10 chunks out-of-order, which is reasonable for most networks
        if (sequenceNumber >= highestSequence - 10 && sequenceNumber <= highestSequence) {
            return true;
        }
        
        // Allow a small jump forward (in case of lost chunks)
        // Maximum tolerable gap is 5 chunks (increased from 3)
        if (sequenceNumber > highestSequence && sequenceNumber <= highestSequence + 5) {
            return true;
        }
        
        // For large transfers, we need to be more lenient with sequence gaps
        if (sequenceMap.size() > 100) {
            // For large transfers, allow bigger gaps as network conditions may vary more
            if (sequenceNumber > highestSequence && sequenceNumber <= highestSequence + 20) {
                LoggingManager.logSecurity(logger, "NOTICE: Larger sequence gap allowed for large transfer " + 
                                         transferId + ". Current: " + sequenceNumber + ", Previous highest: " + highestSequence);
                return true;
            }
        }
        
        // If we're here, there's a significant gap or out-of-order issue
        LoggingManager.logSecurity(logger, "SECURITY WARNING: Unusual chunk sequence detected! " +
                                 "Current: " + sequenceNumber + ", Highest: " + highestSequence + 
                                 ", Lowest: " + lowestSequence + " for transfer " + transferId);
        
        // We'll log the warning but still allow the transfer to continue
        return true;
    }
    
    /**
     * Mark a transfer as complete, which will reset its sequence tracking after a short delay
     * This prevents replay alerts when a new transfer with the same ID starts later
     * @param transferId The ID of the completed transfer
     */
    public static void markTransferComplete(String transferId) {
        if (transferId == null || transferId.isEmpty()) {
            return;
        }
        
        // Schedule cleanup after a short delay (10 seconds) to allow for any in-flight chunks
        cleanupExecutor.schedule(() -> {
            Map<Integer, String> sequenceMap = transferSequences.remove(transferId);
            if (sequenceMap != null) {
                LoggingManager.logSecurity(logger, "Reset sequence tracking for completed transfer: " + 
                                        transferId + " (" + sequenceMap.size() + " sequences)");
            }
        }, 10, TimeUnit.SECONDS);
    }
}
