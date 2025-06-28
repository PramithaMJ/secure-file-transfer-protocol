package common;

import java.io.Serializable;

/**
 * SignedSecureMessage combines a SecureMessage with a digital signature
 * for authentication and non-repudiation in secure file transfers.
 */
public class SignedSecureMessage implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private SecureMessage message;
    private byte[] signature;
    private String senderUsername;
    private long signatureTimestamp;
    
    /**
     * Create a SignedSecureMessage with message and signature
     */
    public SignedSecureMessage(SecureMessage message, byte[] signature) {
        if (message == null || signature == null) {
            throw new IllegalArgumentException("Message and signature cannot be null");
        }
        this.message = message;
        this.signature = signature.clone(); // Defensive copy
        this.signatureTimestamp = System.currentTimeMillis();
    }
    
    /**
     * Create a SignedSecureMessage with sender identification
     */
    public SignedSecureMessage(SecureMessage message, byte[] signature, String senderUsername) {
        this(message, signature);
        this.senderUsername = senderUsername;
    }
    
    public SecureMessage getMessage() { 
        return message; 
    }
    
    public byte[] getSignature() { 
        return signature != null ? signature.clone() : null; // Defensive copy
    }
    
    public String getSenderUsername() { 
        return senderUsername; 
    }
    
    public long getSignatureTimestamp() {
        return signatureTimestamp;
    }
    
    public void setSenderUsername(String senderUsername) { 
        this.senderUsername = senderUsername; 
    }
    
    /**
     * Get a summary of this signed message for logging
     */
    public String getSignatureSummary() {
        StringBuilder summary = new StringBuilder();
        summary.append("SignedSecureMessage{");
        summary.append("sender=").append(senderUsername != null ? senderUsername : "unknown");
        summary.append(", signatureLength=").append(signature != null ? signature.length : 0);
        summary.append(", timestamp=").append(signatureTimestamp);
        if (message != null && message.nonce != null && message.nonce.length() >= 8) {
            summary.append(", nonce=").append(message.nonce.substring(0, 8)).append("...");
        }
        summary.append("}");
        return summary.toString();
    }
    
    /**
     * Validate the basic structure of this signed message
     */
    public boolean isValid() {
        return message != null && 
               signature != null && 
               signature.length > 0 &&
               signatureTimestamp > 0;
    }
    
    @Override
    public String toString() {
        return getSignatureSummary();
    }
}
