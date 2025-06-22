package client;

import common.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.*;
import javax.crypto.*;

public class Client {
    private static final Logger logger = Logger.getLogger(Client.class.getName());
    private static final int CHUNK_SIZE = 4096; // 4KB chunks
    private static final String DOWNLOADS_DIR = "downloads";
    
    private String serverAddress;
    private int serverPort;
    private Socket socket;
    private ObjectOutputStream out;
    private ObjectInputStream in;
    private User user;
    private boolean connected = false;
    private List<User> knownUsers = new ArrayList<>();
    private final Map<String, FileTransferRequest> activeTransfers = new ConcurrentHashMap<>();
    private final Map<String, Boolean> pausedTransfers = new ConcurrentHashMap<>();
    private final Map<String, Integer> transferProgress = new ConcurrentHashMap<>();
    private final ExecutorService transferThreadPool = Executors.newFixedThreadPool(5);
    private final BlockingQueue<Object> messageQueue = new LinkedBlockingQueue<>();
    
    private TransferHistory transferHistory;
    
    private ClientEventListener eventListener;
    
    public Client(String serverAddress, int serverPort) {
        this.serverAddress = serverAddress;
        this.serverPort = serverPort;
        
        File downloadsDir = new File(DOWNLOADS_DIR);
        if (!downloadsDir.exists()) {
            downloadsDir.mkdir();
        }
    }
    
    public void setEventListener(ClientEventListener listener) {
        this.eventListener = listener;
    }
    
    public void connect() throws IOException {
        socket = new Socket(serverAddress, serverPort);
        out = new ObjectOutputStream(socket.getOutputStream());
        in = new ObjectInputStream(socket.getInputStream());
        connected = true;
        
        new Thread(this::processServerMessages).start();
        
        logger.info("Connected to server: " + serverAddress + ":" + serverPort);
    }
    
    public void disconnect() {
        try {
            if (connected) {
                sendToServer("DISCONNECT");
                connected = false;
                if (socket != null && !socket.isClosed()) {
                    socket.close();
                }
                transferThreadPool.shutdown();
            }
        } catch (IOException e) {
            logger.log(Level.WARNING, "Error during disconnect", e);
        }
    }
    
    public boolean login(String username) {
        try {
            if (!connected) {
                connect();
            }
            
            this.user = new User(username);
            
            this.transferHistory = new TransferHistory(username);
            
            sendToServer(user);
            
            Object response = messageQueue.poll(5, TimeUnit.SECONDS);
            
            if (response instanceof String) {
                String msg = (String) response;
                if (msg.startsWith("LOGIN_SUCCESS") || msg.startsWith("REGISTER_SUCCESS")) {
                    logger.info("Logged in as: " + username);
                    return true;
                }
            }
            
            return false;
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error during login", e);
            return false;
        }
    }
    
    public void logout() {
        try {
            if (connected && user != null) {
                sendToServer("LOGOUT");
                user = null;
            }
        } catch (IOException e) {
            logger.log(Level.WARNING, "Error during logout", e);
        }
    }
    
    public List<User> getUserList() {
        try {
            sendToServer("GET_USERS");
            return knownUsers;
        } catch (IOException e) {
            logger.log(Level.WARNING, "Error getting user list", e);
            return new ArrayList<>();
        }
    }
    
    public boolean initiateFileTransfer(String receiverUsername, String filePath) {
        try {
            Path path = Paths.get(filePath);
            if (!Files.exists(path)) {
                logger.warning("File does not exist: " + filePath);
                return false;
            }
            
            File file = path.toFile();
            String fileName = file.getName();
            long fileSize = file.length();
            
            // Find receiver in our known users
            User receiver = null;
            for (User u : knownUsers) {
                if (u.getUsername().equals(receiverUsername)) {
                    receiver = u;
                    break;
                }
            }
            
            if (receiver == null) {
                logger.warning("Receiver not found: " + receiverUsername);
                return false;
            }
            
            PublicKey receiverPublicKey = receiver.getPublicKey();
            if (receiverPublicKey == null) {
                logger.warning("Public key not available for receiver: " + receiverUsername);
                sendToServer("GET_USERS");
                try {
                    Thread.sleep(500);
                    for (User u : knownUsers) {
                        if (u.getUsername().equals(receiverUsername)) {
                            receiverPublicKey = u.getPublicKey();
                            break;
                        }
                    }
                    if (receiverPublicKey == null) {
                        logger.warning("Still no public key for receiver after refresh: " + receiverUsername);
                        return false;
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
            
            logger.info("Using public key of receiver: " + receiverUsername);
            
            SecretKey symmetricKey = CryptoUtils.generateSymmetricKey();
            
            byte[] encryptedSymmetricKey = CryptoUtils.encryptSymmetricKey(symmetricKey, receiverPublicKey);
            
            FileTransferRequest request = new FileTransferRequest(
                user.getUsername(),
                receiverUsername,
                fileName,
                fileSize,
                encryptedSymmetricKey,
                FileTransferRequest.RequestType.INITIATE_TRANSFER
            );
            
            sendToServer(request);
            
            Object response = messageQueue.poll(5, TimeUnit.SECONDS);
            
            if (response instanceof String) {
                String msg = (String) response;
                if (msg.startsWith("TRANSFER_INITIATED")) {
                    String transferId = msg.split("\\|")[1];
                    activeTransfers.put(transferId, request);
                    
                    transferHistory.addTransfer(transferId, fileName, user.getUsername(), 
                                            receiverUsername, fileSize);
                    
                    transferThreadPool.execute(() -> sendFileData(transferId, filePath, symmetricKey));
                    return true;
                }
            }
            
            return false;
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error initiating file transfer", e);
            return false;
        }
    }
    
    private void sendFileData(String transferId, String filePath, SecretKey symmetricKey) {
        try {
            Path path = Paths.get(filePath);
            byte[] fileData = Files.readAllBytes(path);
            
            FileTransferRequest request = activeTransfers.get(transferId);
            if (request == null) {
                logger.warning("Transfer not found: " + transferId);
                return;
            }
            
            List<SecureMessage> encryptedChunks = new ArrayList<>();
            for (int i = 0; i < fileData.length; i += CHUNK_SIZE) {
                int chunkSize = Math.min(CHUNK_SIZE, fileData.length - i);
                byte[] chunk = Arrays.copyOfRange(fileData, i, i + chunkSize);
                
                SecureMessage secureChunk = CryptoUtils.encryptChunk(chunk, symmetricKey, user.getHmacKey());
                encryptedChunks.add(secureChunk);
            }
            
            logger.info("File split into " + encryptedChunks.size() + " encrypted chunks");
            
            Integer startPoint = transferProgress.getOrDefault(transferId, 0);
            
            Socket directSocket = null;
            ObjectOutputStream directOut = null;
            
            try {
                for (int i = startPoint; i < encryptedChunks.size(); i++) {
                    if (Boolean.TRUE.equals(pausedTransfers.get(transferId))) {
                        logger.info("Transfer paused: " + transferId + " at chunk " + i);
                        transferProgress.put(transferId, i);
                        return;
                    }
                    
                    transferProgress.put(transferId, i);
                    
                    SecureMessage chunk = encryptedChunks.get(i);
                    sendToServer("CHUNK|" + transferId + "|" + i + "|" + encryptedChunks.size());
                    sendToServer(chunk);
                    
                    if (eventListener != null) {
                        int progress = (i + 1) * 100 / encryptedChunks.size();
                        eventListener.onTransferProgress(transferId, progress);
                    }
                    
                    Thread.sleep(10);
                }
                
                if (!Boolean.TRUE.equals(pausedTransfers.get(transferId))) {
                    sendToServer("TRANSFER_COMPLETE|" + transferId);
                    
                    TransferRecord record = transferHistory.getTransfer(transferId);
                    if (record != null) {
                        record.complete(filePath);
                        transferHistory.updateTransfer(record);
                    }
                    
                    logger.info("File transfer completed: " + transferId);
                    if (eventListener != null) {
                        eventListener.onTransferComplete(transferId);
                    }
                }
                
            } finally {
                if (directOut != null) directOut.close();
                if (directSocket != null) directSocket.close();
            }
            
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error sending file data", e);
            if (eventListener != null) {
                eventListener.onTransferError(transferId, "Error sending file: " + e.getMessage());
            }
        }
    }
    
    private void receiveFileChunk(String transferId, int chunkIndex, int totalChunks, SecureMessage chunk) {
        try {
            FileTransferRequest request = activeTransfers.get(transferId);
            if (request == null) {
                logger.warning("Transfer not found for chunk: " + transferId);
                return;
            }
            
            if (request.getEncryptedSymmetricKey() == null) {
                logger.warning("No encrypted key available for transfer: " + transferId);
                if (eventListener != null) {
                    eventListener.onTransferError(transferId, "No encryption key available");
                }
                return;
            }
            
            if (user.getPublicKey() == null) {
                logger.warning("No public key available for current user: " + user.getUsername());
                if (eventListener != null) {
                    eventListener.onTransferError(transferId, "Public key not available for decryption");
                }
                return;
            }
            
            String downloadPath = DOWNLOADS_DIR + File.separator + request.getFileName();
            File downloadFile = new File(downloadPath);
            
            SecretKey symmetricKey;
            try {
                symmetricKey = CryptoUtils.decryptSymmetricKey(
                    request.getEncryptedSymmetricKey(), 
                    user.getPrivateKey()
                );
            } catch (javax.crypto.BadPaddingException e) {
                logger.warning("Cannot decrypt the symmetric key, possibly wrong public key was used: " + e.getMessage());
                if (eventListener != null) {
                    eventListener.onTransferError(transferId, "Cannot decrypt the file: incorrect key");
                }
                return;
            }
            
            if (!CryptoUtils.verifyIntegrity(chunk, user.getHmacKey())) {
                logger.warning("Integrity check failed for chunk: " + chunkIndex);
                if (eventListener != null) {
                    eventListener.onTransferError(transferId, "Integrity check failed for chunk: " + chunkIndex);
                }
                return;
            }
            
            // Decrypt chunk
            byte[] decryptedChunk = CryptoUtils.decryptChunk(chunk, symmetricKey);
            
            try (FileOutputStream fos = new FileOutputStream(downloadFile, true)) {
                fos.write(decryptedChunk);
            }
            
            if (eventListener != null) {
                int progress = (chunkIndex + 1) * 100 / totalChunks;
                eventListener.onTransferProgress(transferId, progress);
            }
            
            // If last chunk, mark as complete
            if (chunkIndex == totalChunks - 1) {
                logger.info("File transfer completed: " + request.getFileName());
                if (eventListener != null) {
                    eventListener.onTransferComplete(transferId);
                }
            }
            
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error receiving file chunk", e);
            if (eventListener != null) {
                eventListener.onTransferError(transferId, "Error receiving chunk: " + e.getMessage());
            }
        }
    }
    
    private void sendToServer(Object message) throws IOException {
        synchronized (out) {
            out.writeObject(message);
            out.flush();
        }
    }
    
    private void processServerMessages() {
        try {
            while (connected) {
                Object message = in.readObject();
                processMessage(message);
            }
        } catch (EOFException e) {
            logger.info("Server closed the connection");
        } catch (IOException | ClassNotFoundException e) {
            logger.log(Level.WARNING, "Error processing server messages", e);
        } finally {
            connected = false;
            if (eventListener != null) {
                eventListener.onDisconnect();
            }
        }
    }
    
    private void processMessage(Object message) {
        try {
            if (message instanceof String) {
                String strMessage = (String) message;
                processStringMessage(strMessage);
            } else if (message instanceof List<?>) {
                @SuppressWarnings("unchecked")
                List<User> users = (List<User>) message;
                knownUsers = users;
                if (eventListener != null) {
                    eventListener.onUserListUpdated(knownUsers);
                }
            } else if (message instanceof FileTransferRequest) {
                FileTransferRequest request = (FileTransferRequest) message;
                if (request.getReceiverUsername().equals(user.getUsername())) {

                    String transferId = null;
                    for (Map.Entry<String, FileTransferRequest> entry : activeTransfers.entrySet()) {
                        if (entry.getValue().getSenderUsername().equals(request.getSenderUsername()) && 
                            entry.getValue().getFileName().equals(request.getFileName())) {
                            transferId = entry.getKey();
                            break;
                        }
                    }
                    
                    if (transferId == null) {
                        transferId = UUID.randomUUID().toString();
                        transferHistory.addTransfer(transferId, request.getFileName(), 
                                                  request.getSenderUsername(),
                                                  user.getUsername(), 
                                                  request.getFileSize());
                    } else {
                        logger.info("Updating existing transfer request with ID: " + transferId);
                    }
                    
                    activeTransfers.put(transferId, request);
                    
                    logger.info("Storing transfer request with ID: " + transferId);
                    
                    if (eventListener != null) {
                        eventListener.onFileTransferRequest(request);
                    }
                }
            } else if (message instanceof SecureMessage) {
            }
        } catch (Exception e) {
            logger.log(Level.WARNING, "Error processing message", e);
        }
    }
    
    private void processStringMessage(String message) {
        String[] parts = message.split("\\|");
        String command = parts[0];
        
        switch (command) {
            case "LOGIN_SUCCESS":
            case "REGISTER_SUCCESS":
            case "LOGOUT_ACK":
            case "TRANSFER_INITIATED":
                messageQueue.offer(message);
                break;
                
            case "PAUSE_TRANSFER":
                if (parts.length >= 2) {
                    String transferId = parts[1];
                    logger.info("Received pause request for transfer: " + transferId);
                    pausedTransfers.put(transferId, true);
                    
                    TransferRecord record = transferHistory.getTransfer(transferId);
                    if (record != null) {
                        record.pause();
                        transferHistory.updateTransfer(record);
                    }
                    
                    if (eventListener != null) {
                        eventListener.onTransferPaused(transferId);
                    }
                }
                break;
                
            case "PAUSE_TRANSFER_ACK":
                if (parts.length >= 2) {
                    String transferId = parts[1];
                    logger.info("Server acknowledged pause for transfer: " + transferId);
                    pausedTransfers.put(transferId, true);
                }
                break;
                
            case "RESUME_TRANSFER":
                if (parts.length >= 2) {
                    String transferId = parts[1];
                    logger.info("Received resume request for transfer: " + transferId);
                    pausedTransfers.put(transferId, false);
                    
                    TransferRecord record = transferHistory.getTransfer(transferId);
                    if (record != null) {
                        record.resume();
                        transferHistory.updateTransfer(record);
                    }
                    
                    if (eventListener != null) {
                        eventListener.onTransferResumed(transferId);
                    }
                }
                break;
                
            case "RESUME_TRANSFER_ACK":
                if (parts.length >= 2) {
                    String transferId = parts[1];
                    logger.info("Server acknowledged resume for transfer: " + transferId);
                    pausedTransfers.put(transferId, false);
                    
                    FileTransferRequest request = activeTransfers.get(transferId);
                    if (request != null && request.getSenderUsername().equals(user.getUsername())) {
                        transferThreadPool.execute(() -> {
                            try {
                                TransferRecord record = transferHistory.getTransfer(transferId);
                                String filePath = record != null ? record.getFilePath() : request.getFileName();
                                
                                SecretKey symmetricKey = CryptoUtils.generateSymmetricKey();
                                sendFileData(transferId, filePath, symmetricKey);
                            } catch (Exception e) {
                                logger.log(Level.SEVERE, "Error resuming file transfer", e);
                            }
                        });
                    }
                }
                break;
                
            case "USER_STATUS":
                if (parts.length >= 3) {
                    String username = parts[1];
                    boolean online = "online".equals(parts[2]);
                    
                    for (User u : knownUsers) {
                        if (u.getUsername().equals(username)) {
                            u.setOnline(online);
                            break;
                        }
                    }
                    
                    if (eventListener != null) {
                        eventListener.onUserStatusChange(username, online);
                    }
                }
                break;
                
            case "TRANSFER_REQUEST":
                if (parts.length >= 5) {
                    String transferId = parts[1];
                    String sender = parts[2];
                    String fileName = parts[3];
                    long fileSize = Long.parseLong(parts[4]);
                    
                    logger.info("Received transfer request: " + fileName + " from " + sender);

                    FileTransferRequest prelimRequest = new FileTransferRequest(
                        sender,
                        user.getUsername(),
                        fileName,
                        fileSize,
                        null,
                        FileTransferRequest.RequestType.INITIATE_TRANSFER
                    );
                    
                    activeTransfers.put(transferId, prelimRequest);
                    }
                break;
                
            case "CHUNK":
                if (parts.length >= 4) {
                    String transferId = parts[1];
                    int chunkIndex = Integer.parseInt(parts[2]);
                    int totalChunks = Integer.parseInt(parts[3]);
                    
                    try {
                        Object chunkObj = in.readObject();
                        if (chunkObj instanceof SecureMessage) {
                            receiveFileChunk(transferId, chunkIndex, totalChunks, (SecureMessage) chunkObj);
                        }
                    } catch (Exception e) {
                        logger.log(Level.WARNING, "Error receiving chunk", e);
                    }
                }
                break;
                
            case "TRANSFER_COMPLETE":
                if (parts.length >= 2) {
                    String transferId = parts[1];
                    activeTransfers.remove(transferId);
                    logger.info("Transfer completed: " + transferId);
                }
                break;
                
            case "ERROR":
                if (parts.length >= 2) {
                    String errorMsg = parts[1];
                    logger.warning("Server error: " + errorMsg);
                    if (eventListener != null) {
                        eventListener.onError(errorMsg);
                    }
                }
                break;
        }
    }
    
    public User getCurrentUser() {
        return user;
    }
    
    public boolean isConnected() {
        return connected;
    }
    
    public boolean pauseTransfer(String transferId) {
        try {
            FileTransferRequest request = activeTransfers.get(transferId);
            if (request == null) {
                logger.warning("Transfer not found: " + transferId);
                return false;
            }
            
            pausedTransfers.put(transferId, true);
            
            FileTransferRequest pauseRequest = new FileTransferRequest(
                request.getSenderUsername(),
                request.getReceiverUsername(),
                request.getFileName(),
                request.getFileSize(),
                request.getEncryptedSymmetricKey(),
                FileTransferRequest.RequestType.PAUSE_TRANSFER
            );
            
            sendToServer("PAUSE_TRANSFER|" + transferId);
            sendToServer(pauseRequest);
            
            TransferRecord record = transferHistory.getTransfer(transferId);
            if (record != null) {
                record.pause();
                transferHistory.updateTransfer(record);
            }
            
            if (eventListener != null) {
                eventListener.onTransferPaused(transferId);
            }
            
            return true;
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error pausing transfer", e);
            return false;
        }
    }
    
    public boolean resumeTransfer(String transferId) {
        try {
            FileTransferRequest request = activeTransfers.get(transferId);
            if (request == null) {
                logger.warning("Transfer not found: " + transferId);
                return false;
            }
            
            pausedTransfers.put(transferId, false);
            
            FileTransferRequest resumeRequest = new FileTransferRequest(
                request.getSenderUsername(),
                request.getReceiverUsername(),
                request.getFileName(),
                request.getFileSize(),
                request.getEncryptedSymmetricKey(),
                FileTransferRequest.RequestType.RESUME_TRANSFER
            );
            
            sendToServer("RESUME_TRANSFER|" + transferId);
            sendToServer(resumeRequest);
            
            TransferRecord record = transferHistory.getTransfer(transferId);
            if (record != null) {
                record.resume();
                transferHistory.updateTransfer(record);
            }
            
            if (request.getSenderUsername().equals(user.getUsername())) {
                Integer lastChunk = transferProgress.get(transferId);
                if (lastChunk != null) {
                }
            }
            
            if (eventListener != null) {
                eventListener.onTransferResumed(transferId);
            }
            
            return true;
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error resuming transfer", e);
            return false;
        }
    }
    
    public interface ClientEventListener {
        void onUserListUpdated(List<User> users);
        void onUserStatusChange(String username, boolean online);
        void onFileTransferRequest(FileTransferRequest request);
        void onTransferProgress(String transferId, int progress);
        void onTransferComplete(String transferId);
        void onTransferError(String transferId, String error);
        void onDisconnect();
        void onError(String error);
        void onTransferPaused(String transferId);
        void onTransferResumed(String transferId);
    }
}
