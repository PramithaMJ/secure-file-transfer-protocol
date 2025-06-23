package common;

import java.io.Serializable;

public class FileTransferRequest implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private String senderUsername;
    private String receiverUsername;
    private String fileName;
    private long fileSize;
    private byte[] encryptedSymmetricKey;
    private byte[] encryptedHmacKey;
    private RequestType type;
    
    public enum RequestType {
        INITIATE_TRANSFER,
        ACKNOWLEDGE_KEY,
        TRANSFER_CHUNK,
        TRANSFER_COMPLETE,
        TRANSFER_ERROR,
        PAUSE_TRANSFER,
        RESUME_TRANSFER
    }
    
    public FileTransferRequest(String senderUsername, String receiverUsername, String fileName, 
                             long fileSize, byte[] encryptedSymmetricKey, RequestType type) {
        this(senderUsername, receiverUsername, fileName, fileSize, encryptedSymmetricKey, null, type);
    }
    
    public FileTransferRequest(String senderUsername, String receiverUsername, String fileName, 
                             long fileSize, byte[] encryptedSymmetricKey, byte[] encryptedHmacKey, RequestType type) {
        this.senderUsername = senderUsername;
        this.receiverUsername = receiverUsername;
        this.fileName = fileName;
        this.fileSize = fileSize;
        this.encryptedSymmetricKey = encryptedSymmetricKey;
        this.encryptedHmacKey = encryptedHmacKey;
        this.type = type;
    }
    
    public String getSenderUsername() {
        return senderUsername;
    }
    
    public String getReceiverUsername() {
        return receiverUsername;
    }
    
    public String getFileName() {
        return fileName;
    }
    
    public long getFileSize() {
        return fileSize;
    }
    
    public byte[] getEncryptedSymmetricKey() {
        return encryptedSymmetricKey;
    }
    
    public byte[] getEncryptedHmacKey() {
        return encryptedHmacKey;
    }
    
    public RequestType getType() {
        return type;
    }
    
    public void setType(RequestType type) {
        this.type = type;
    }
    
    @Override
    public String toString() {
        return "FileTransferRequest{" +
                "sender='" + senderUsername + '\'' +
                ", receiver='" + receiverUsername + '\'' +
                ", fileName='" + fileName + '\'' +
                ", fileSize=" + fileSize +
                ", type=" + type +
                ", hasSymmetricKey=" + (encryptedSymmetricKey != null) +
                ", hasHmacKey=" + (encryptedHmacKey != null) +
                '}';
    }
}
