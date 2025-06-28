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
    public static final int AES_KEY_SIZE = 256;
    public static final int CHUNK_SIZE = 4096; // 4KB chunks
    
    // Anti-replay protection constants
    private static final long MAX_MESSAGE_AGE_MS = 5 * 60 * 1000; // 5 minutes
    private static final int MAX_NONCE_CACHE_SIZE = 10000; // Limit memory usage
    
    // Nonce tracking for replay protection - stores nonce -> timestamp
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
        // Input validation for security
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

        // Generate timestamp and cryptographically nonce for replay protection
        long timestamp = System.currentTimeMillis();
        String nonce = generateSecureNonce();

        // Calculate HMAC for integrity
        Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
        hmac.init(hmacKey);

        // HMAC over encrypted data + IV + timestamp + nonce ( UTF-8 encoding)
        hmac.update(encryptedChunk);
        hmac.update(iv);
        hmac.update(String.valueOf(timestamp).getBytes("UTF-8"));
        hmac.update(nonce.getBytes("UTF-8"));
        byte[] mac = hmac.doFinal();

        return new SecureMessage(encryptedChunk, mac, iv, timestamp, nonce);
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
     * Verify message integrity using HMAC with anti-replay protection
     * 
     */
    public static boolean verifyIntegrity(SecureMessage message, SecretKey hmacKey) throws Exception {
        // Input validation for security
        if (message == null || hmacKey == null) {
            throw new IllegalArgumentException("Message and HMAC key cannot be null");
        }
        if (message.nonce == null || message.nonce.trim().isEmpty()) {
            throw new IllegalArgumentException("Message nonce cannot be null or empty");
        }
        
        // 1. ANTI-REPLAY: Check timestamp window - reject messages older than 5 minutes
        long currentTime = System.currentTimeMillis();
        long messageAge = currentTime - message.timestamp;
        
        if (messageAge > MAX_MESSAGE_AGE_MS) {
            // Message is too old - potential replay attack detected
            LoggingManager.logSecurity(logger, "SECURITY ALERT: Message rejected - too old (age: " + 
                                     (messageAge / 1000) + "s). Potential replay attack detected.");
            return false;
        }
        
        if (messageAge < -60000) { // Allow 1 minute clock skew into future
            // Message from future - potential clock manipulation
            LoggingManager.logSecurity(logger, "SECURITY ALERT: Message rejected - from future. Potential clock manipulation detected.");
            return false;
        }
        
        // 2. ANTI-REPLAY: Check nonce uniqueness within time window
        // Create composite key to avoid nonce collisions across different timestamps
        String nonceKey = message.nonce + ":" + message.timestamp;
        Long existingTimestamp = usedNonces.get(nonceKey);
        if (existingTimestamp != null) {    
            LoggingManager.logSecurity(logger, "SECURITY ALERT: Replay attack detected! Duplicate nonce: " + message.nonce);
            return false;
        }
        
        // 3. Verify MAC calculation with same method used in encryption
        Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
        hmac.init(hmacKey);
        hmac.update(message.encryptedData);
        hmac.update(message.iv);
        hmac.update(String.valueOf(message.timestamp).getBytes("UTF-8"));
        hmac.update(message.nonce.getBytes("UTF-8"));

        byte[] computedMac = hmac.doFinal();
        
        // Use timing-safe comparison to prevent timing attacks
        boolean macValid = MessageDigest.isEqual(computedMac, message.mac);
        
        // 4. ANTI-REPLAY: Only add nonce to used set if MAC is valid
        if (macValid) {
            usedNonces.put(nonceKey, currentTime);
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
     * Get the number of tracked nonces (for testing and monitoring)
     */
    public static int getTrackedNonceCount() {
        return usedNonces.size();
    }
    
    /**
     * Clear all tracked nonces (for testing)
     * WARNING: Only use this in test environments
     */
    public static void clearNonceCache() {
        usedNonces.clear();
        LoggingManager.logSecurity(logger, "ADMIN: Nonce cache cleared manually");
    }
    
    /**
     * Force cleanup of old nonces (for testing)
     */
    public static void forceNonceCleanup() {
        int sizeBefore = usedNonces.size();
        cleanupOldNonces();
        int sizeAfter = usedNonces.size();
        LoggingManager.logSecurity(logger, "ADMIN: Forced nonce cleanup - removed " + (sizeBefore - sizeAfter) + " old nonces");
    }
    
    /**
     * Check if a nonce has been used (for testing)
     */
    public static boolean isNonceUsed(String nonce, long timestamp) {
        String nonceKey = nonce + ":" + timestamp;
        return usedNonces.containsKey(nonceKey);
    }
    
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
}
