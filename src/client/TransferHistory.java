package client;

import common.TransferRecord;
import java.io.*;
import java.util.*;
import java.util.logging.*;

public class TransferHistory {
    private static final Logger logger = Logger.getLogger(TransferHistory.class.getName());
    private static final String HISTORY_FILE = "transfer_history.dat";
    
    private List<TransferRecord> transferRecords;
    private String username;
    
    public TransferHistory(String username) {
        this.username = username;
        this.transferRecords = new ArrayList<>();
        loadHistory();
    } 

    public TransferRecord addTransfer(String transferId, String fileName, String senderUsername, 
                                    String receiverUsername, long fileSize) {
        TransferRecord record = new TransferRecord(transferId, fileName, senderUsername, 
                                                 receiverUsername, fileSize);
        transferRecords.add(record);
        saveHistory();
        return record;
    }

    public TransferRecord getTransfer(String transferId) {
        for (TransferRecord record : transferRecords) {
            if (record.getTransferId().equals(transferId)) {
                return record;
            }
        }
        return null;
    }

    public void updateTransfer(TransferRecord record) {
        saveHistory();
    }

    public List<TransferRecord> getAllTransfers() {
        return new ArrayList<>(transferRecords);
    }
    
    public List<TransferRecord> getSentTransfers() {
        List<TransferRecord> result = new ArrayList<>();
        for (TransferRecord record : transferRecords) {
            if (record.getSenderUsername().equals(username)) {
                result.add(record);
            }
        }
        return result;
    }

    public List<TransferRecord> getReceivedTransfers() {
        List<TransferRecord> result = new ArrayList<>();
        for (TransferRecord record : transferRecords) {
            if (record.getReceiverUsername().equals(username)) {
                result.add(record);
            }
        }
        return result;
    }
    
    public List<TransferRecord> getActiveTransfers() {
        List<TransferRecord> result = new ArrayList<>();
        for (TransferRecord record : transferRecords) {
            if (record.getStatus() == TransferRecord.TransferStatus.IN_PROGRESS ||
                record.getStatus() == TransferRecord.TransferStatus.PAUSED) {
                result.add(record);
            }
        }
        return result;
    }
    
    private void saveHistory() {
        try (ObjectOutputStream oos = new ObjectOutputStream(
                new FileOutputStream(username + "_" + HISTORY_FILE))) {
            oos.writeObject(transferRecords);
            logger.info("Transfer history saved");
        } catch (IOException e) {
            logger.log(Level.WARNING, "Failed to save transfer history", e);
        }
    }

    @SuppressWarnings("unchecked")
    private void loadHistory() {
        File historyFile = new File(username + "_" + HISTORY_FILE);
        if (!historyFile.exists()) {
            logger.info("No history file found for user " + username);
            return;
        }
        
        try (ObjectInputStream ois = new ObjectInputStream(
                new FileInputStream(historyFile))) {
            transferRecords = (List<TransferRecord>) ois.readObject();
            logger.info("Loaded " + transferRecords.size() + " transfer records from history");
        } catch (IOException | ClassNotFoundException e) {
            logger.log(Level.WARNING, "Failed to load transfer history", e);
        }
    }
}
