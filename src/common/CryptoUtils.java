package common;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.*;

public class CryptoUtils {
    public static final String RSA_ALGORITHM = "RSA";
    public static final String AES_ALGORITHM = "AES";
    public static final String AES_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    public static final String RSA_TRANSFORMATION = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";
    public static final String HMAC_ALGORITHM = "HmacSHA256";
    public static final int AES_KEY_SIZE = 256;
    public static final int CHUNK_SIZE = 4096; // 4KB chunks
    
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
     */
    public static byte[] encryptSymmetricKey(SecretKey symmetricKey, PublicKey recipientPublicKey) 
            throws Exception {
        Cipher rsaCipher = Cipher.getInstance(RSA_TRANSFORMATION);
        rsaCipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey);
        return rsaCipher.doFinal(symmetricKey.getEncoded());
    }
    
    /**
     * Decrypt a symmetric key with user's private key
     */
    public static SecretKey decryptSymmetricKey(byte[] encryptedKey, PrivateKey privateKey) 
            throws Exception {
        Cipher rsaCipher = Cipher.getInstance(RSA_TRANSFORMATION);
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] keyBytes = rsaCipher.doFinal(encryptedKey);
        return new SecretKeySpec(keyBytes, AES_ALGORITHM);
    }
    
    /**
     * Encrypt a chunk of data and create a secure message
     */
    public static SecureMessage encryptChunk(byte[] chunk, SecretKey symmetricKey, SecretKey hmacKey)
            throws Exception {
        // Generate IV for CBC mode
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Encrypt chunk
        Cipher aesCipher = Cipher.getInstance(AES_TRANSFORMATION);
        aesCipher.init(Cipher.ENCRYPT_MODE, symmetricKey, ivSpec);
        byte[] encryptedChunk = aesCipher.doFinal(chunk);

        // Generate timestamp and nonce for replay protection
        long timestamp = Instant.now().toEpochMilli();
        String nonce = UUID.randomUUID().toString();

        // Calculate HMAC for integrity
        Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
        hmac.init(hmacKey);

        // HMAC over encrypted data + IV + timestamp + nonce
        hmac.update(encryptedChunk);
        hmac.update(iv);
        hmac.update(String.valueOf(timestamp).getBytes());
        hmac.update(nonce.getBytes());
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
     * Verify message integrity using HMAC
     */
    public static boolean verifyIntegrity(SecureMessage message, SecretKey hmacKey) throws Exception {
        Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
        hmac.init(hmacKey);

        hmac.update(message.encryptedData);
        hmac.update(message.iv);
        hmac.update(String.valueOf(message.timestamp).getBytes());
        hmac.update(message.nonce.getBytes());

        byte[] computedMac = hmac.doFinal();

        return MessageDigest.isEqual(computedMac, message.mac);
    }
    
    public static PublicKey bytesToPublicKey(byte[] keyBytes) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return keyFactory.generatePublic(keySpec);
    }
}
