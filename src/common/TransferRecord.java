package common;

import java.io.Serializable;
import java.util.Date;

public class TransferRecord implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private String transferId;
    private String fileName;
    private String senderUsername;
    private String receiverUsername;
    private long fileSize;
    private Date startTime;
    private Date completionTime;
    private TransferStatus status;
    private String filePath;
    
    public enum TransferStatus {
        IN_PROGRESS,
        COMPLETED,
        FAILED,
        CANCELED,
        PAUSED
    }
    
    public TransferRecord(String transferId, String fileName, String senderUsername, 
                         String receiverUsername, long fileSize) {
        this.transferId = transferId;
        this.fileName = fileName;
        this.senderUsername = senderUsername;
        this.receiverUsername = receiverUsername;
        this.fileSize = fileSize;
        this.startTime = new Date();
        this.status = TransferStatus.IN_PROGRESS;
    }
    
    public void complete(String filePath) {
        this.status = TransferStatus.COMPLETED;
        this.completionTime = new Date();
        this.filePath = filePath;
    }
    
    public void fail() {
        this.status = TransferStatus.FAILED;
        this.completionTime = new Date();
    }
    
    public void cancel() {
        this.status = TransferStatus.CANCELED;
        this.completionTime = new Date();
    }
    
    public void pause() {
        this.status = TransferStatus.PAUSED;
    }
    
    public void resume() {
        this.status = TransferStatus.IN_PROGRESS;
    }
    
    public long getDuration() {
        if (completionTime == null) {
            return new Date().getTime() - startTime.getTime();
        }
        return completionTime.getTime() - startTime.getTime();
    }
    
    public String getTransferId() {
        return transferId;
    }
    
    public String getFileName() {
        return fileName;
    }
    
    public String getSenderUsername() {
        return senderUsername;
    }
    
    public String getReceiverUsername() {
        return receiverUsername;
    }
    
    public long getFileSize() {
        return fileSize;
    }
    
    public Date getStartTime() {
        return startTime;
    }
    
    public Date getCompletionTime() {
        return completionTime;
    }
    
    public TransferStatus getStatus() {
        return status;
    }
    
    public String getFilePath() {
        return filePath;
    }
}
