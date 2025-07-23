package common;

import javax.crypto.*;
import java.io.Serializable;
import java.security.*;


public class Participant implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private transient KeyPair rsaKeyPair;
    private transient SecretKey hmacKey;
    
    private byte[] serializedPublicKey;
    
    protected static final String RSA_ALGORITHM = "RSA";
    protected static final String HMAC_ALGORITHM = "HmacSHA256";
    protected static final int RSA_KEY_SIZE = 2048;

    public Participant() throws NoSuchAlgorithmException {
        // Generate RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyGen.initialize(RSA_KEY_SIZE);
        this.rsaKeyPair = keyGen.generateKeyPair();

        // Generate HMAC key
        KeyGenerator hmacKeyGen = KeyGenerator.getInstance(HMAC_ALGORITHM);
        hmacKeyGen.init(256);
        this.hmacKey = hmacKeyGen.generateKey();
        
        // Store serialized form of public key
        this.serializedPublicKey = rsaKeyPair.getPublic().getEncoded();
    }
    
    public Participant(byte[] serializedPublicKey) throws NoSuchAlgorithmException {
        this();
        this.serializedPublicKey = serializedPublicKey;
        
        // SECURITY: Validate the provided public key
        try {
            PublicKey key = CryptoUtils.bytesToPublicKey(serializedPublicKey);
            CryptoUtils.validatePublicKey(key);
        } catch (Exception e) {
            throw new SecurityException("Invalid public key provided: " + e.getMessage(), e);
        }
    }

    public PublicKey getPublicKey() {
        try {
            if (rsaKeyPair == null && serializedPublicKey != null) {
                return CryptoUtils.bytesToPublicKey(serializedPublicKey);
            }
            return rsaKeyPair.getPublic();
        } catch (Exception e) {
            if (rsaKeyPair != null) {
                return rsaKeyPair.getPublic();
            }
            return null;
        }
    }

    public PrivateKey getPrivateKey() {
        return rsaKeyPair != null ? rsaKeyPair.getPrivate() : null;
    }

    public SecretKey getHmacKey() {
        return hmacKey;
    }
    
    public byte[] getSerializedPublicKey() {
        return serializedPublicKey;
    }
    
    public void setSerializedPublicKey(byte[] publicKeyBytes) {
        // Validate the public key before accepting it
        try {
            PublicKey key = CryptoUtils.bytesToPublicKey(publicKeyBytes);
            CryptoUtils.validatePublicKey(key);
            this.serializedPublicKey = publicKeyBytes;
        } catch (Exception e) {
            throw new SecurityException("Invalid public key provided: " + e.getMessage(), e);
        }
    }
}
