package server;

import common.*;
import common.SecureMessage;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ServerConnectionHandler implements Runnable {
    private static final Logger logger = LoggingManager.getLogger(ServerConnectionHandler.class.getName());
    
    private Socket clientSocket;
    private ObjectInputStream in;
    private ObjectOutputStream out;
    private UserManager userManager;
    private SessionManager sessionManager;
    private RateLimitManager rateLimitManager;
    private User currentUser;
    private String currentSessionToken;
    private boolean running;
    private String clientIP;
    
    private static final Map<String, FileTransferRequest> activeTransfers = new HashMap<>();
    
    public ServerConnectionHandler(Socket clientSocket, UserManager userManager, SessionManager sessionManager, RateLimitManager rateLimitManager) {
        this.clientSocket = clientSocket;
        this.userManager = userManager;
        this.sessionManager = sessionManager;
        this.rateLimitManager = rateLimitManager;
        this.clientIP = clientSocket.getInetAddress().getHostAddress();
        this.running = true;
    }
    
    @Override
    public void run() {
        try {
            out = new ObjectOutputStream(clientSocket.getOutputStream());
            in = new ObjectInputStream(clientSocket.getInputStream());
            
            while (running) {
                Object message = in.readObject();
                processMessage(message);
            }
        } catch (EOFException e) {
            logger.info("Client disconnected: " + (currentUser != null ? currentUser.getUsername() : "unknown"));
        } catch (IOException | ClassNotFoundException e) {
            logger.log(Level.WARNING, "Error handling client connection", e);
        } finally {
            cleanup();
        }
    }
    
    private void processMessage(Object message) {
        try {
            // Skip rate limiting for file chunk transfers and their associated objects
            boolean isChunkTransfer = false;
            if (message instanceof String) {
                String command = (String) message;
                isChunkTransfer = command.startsWith("CHUNK") || command.startsWith("SIGNED_CHUNK");
            } else if (message instanceof SecureMessage || message instanceof SignedSecureMessage) {
                // These objects are part of chunk transfers and should be exempt from rate limiting
                isChunkTransfer = true;
            }
            
            // Only apply rate limiting for non-chunk transfers
            if (!isChunkTransfer && !rateLimitManager.allowRequest(clientIP)) {
                logger.warning("Request rate limit exceeded for IP: " + clientIP);
                sendError("Rate limit exceeded. Please slow down your requests.");
                return;
            }
            
            if (message instanceof String) {
                String command = (String) message;
                processCommand(command);
                
            } else if (message instanceof User) {
                User user = (User) message;
                handleUserLogin(user);
                
            } else if (message instanceof FileTransferRequest) {
                FileTransferRequest request = (FileTransferRequest) message;
                handleFileTransferRequest(request);
                
            } else if (message instanceof SecureMessage) {
                SecureMessage chunk = (SecureMessage) message;
                handleFileChunk(chunk);
            }
        } catch (Exception e) {
            logger.log(Level.WARNING, "Error processing message", e);
            sendError("Error processing message: " + e.getMessage());
        }
    }
    
    private void processCommand(String command) throws IOException {
        String[] parts = command.split("\\|");
        String cmd = parts[0];
        
        switch (cmd) {
            case "LOGOUT":
                handleLogout();
                break;
                
            case "REFRESH_SESSION":
                if (requireValidSession()) {
                    send("SESSION_REFRESHED");
                }
                break;
                
            case "GET_USERS":
                if (requireValidSession()) {
                    sendUsersList();
                }
                break;
                
            case "DISCONNECT":
                running = false;
                break;
                
            case "PAUSE_TRANSFER":
                if (requireValidSession() && parts.length >= 2) {
                    String transferId = parts[1];
                    handlePauseTransfer(transferId);
                }
                break;
                
            case "RESUME_TRANSFER":
                if (requireValidSession() && parts.length >= 2) {
                    String transferId = parts[1];
                    handleResumeTransfer(transferId);
                }
                break;
                
            case "CHUNK":
                if (requireValidSession() && parts.length >= 4) {
                    String transferId = parts[1];
                    int chunkIndex = Integer.parseInt(parts[2]);
                    int totalChunks = Integer.parseInt(parts[3]);
                    handleChunkCommand(transferId, chunkIndex, totalChunks);
                } else if (!requireValidSession()) {
                } else {
                    sendError("Invalid CHUNK command format");
                }
                break;
                
            case "SIGNED_CHUNK":
                if (parts.length >= 4) {
                    String transferId = parts[1];
                    int chunkIndex = Integer.parseInt(parts[2]);
                    int totalChunks = Integer.parseInt(parts[3]);
                    handleSignedChunkCommand(transferId, chunkIndex, totalChunks);
                } else {
                    sendError("Invalid SIGNED_CHUNK command format");
                }
                break;
                
            case "TRANSFER_COMPLETE":
                if (parts.length >= 2) {
                    String transferId = parts[1];
                    handleTransferComplete(transferId);
                } else {
                    sendError("Invalid TRANSFER_COMPLETE command format");
                }
                break;
                
            case "ACCEPT_TRANSFER":
                if (parts.length >= 2) {
                    String transferId = parts[1];
                    handleAcceptTransfer(transferId);
                }
                break;
                
            case "REJECT_TRANSFER":
                if (parts.length >= 2) {
                    String transferId = parts[1];
                    handleRejectTransfer(transferId);
                }
                break;
                
            default:
                logger.warning("Unknown command: " + cmd);
                sendError("Unknown command: " + cmd);
        }
    }
    
    private void handleUserLogin(User user) throws IOException {
        String username = user.getUsername();
        
        if (!rateLimitManager.allowLoginAttempt(clientIP)) {
            logger.warning("Login rate limit exceeded for IP: " + clientIP);
            send("LOGIN_FAILED|Too many login attempts. Please try again later.");
            return;
        }
        
        User existingUser = userManager.getUser(username);
        
        if (existingUser == null) {
            userManager.addUser(user);
            currentUser = user;
            currentUser.setOnline(true);
            
            currentSessionToken = sessionManager.createSession(username);
            
            LoggingManager.logSecurity(logger, "New user registered: " + username + " from IP: " + clientIP);
            send("REGISTER_SUCCESS|" + username + "|" + currentSessionToken);
        } else {
            currentUser = existingUser;
            currentUser.setOnline(true);
            
            currentSessionToken = sessionManager.createSession(username);
            
            LoggingManager.logSecurity(logger, "User logged in: " + username + " from IP: " + clientIP +
                                     ", Session: " + currentSessionToken.substring(0, 8) + "...");
            send("LOGIN_SUCCESS|" + username + "|" + currentSessionToken);
        }
        
        userManager.registerConnection(username, this);
        userManager.broadcastUserStatus(currentUser);
        
        startSessionMonitoring();
        
        sendUsersList();
    }
    
    private void handleFileTransferRequest(FileTransferRequest request) throws IOException {
        String sender = request.getSenderUsername();
        String receiver = request.getReceiverUsername();
        
        logger.info("File transfer request from " + sender + " to " + receiver + ": " + request.getFileName());
        
        User receiverUser = userManager.getUser(receiver);
        if (receiverUser == null || !receiverUser.isOnline()) {
            sendError("Recipient " + receiver + " not found or offline");
            return;
        }
        
        String transferId = UUID.randomUUID().toString();
        activeTransfers.put(transferId, request);
        
        userManager.forwardFileTransferRequest(request, transferId);
        
        send("TRANSFER_INITIATED|" + transferId);
    }
    
    private void handleFileChunk(SecureMessage chunk) {
        try {
            int chunkSize = chunk.encryptedData != null ? chunk.encryptedData.length : 0;
            if (!rateLimitManager.allowBandwidth(clientIP, chunkSize)) {
                logger.warning("Bandwidth limit exceeded for IP: " + clientIP);
                sendError("Bandwidth limit exceeded. Transfer throttled.");
                return;
            }
            
            logger.info("Processing file chunk of size: " + chunkSize + " bytes from IP: " + clientIP);
            
        } catch (Exception e) {
            logger.log(Level.WARNING, "Error handling file chunk", e);
            sendError("Error processing file chunk: " + e.getMessage());
        }
    }
    
    private void handlePauseTransfer(String transferId) throws IOException {
        FileTransferRequest request = activeTransfers.get(transferId);
        if (request == null) {
            sendError("Transfer not found: " + transferId);
            return;
        }
        
        logger.info("Pausing transfer: " + transferId);
        
        send("PAUSE_TRANSFER_ACK|" + transferId);
        
        User receiver = userManager.getUser(request.getReceiverUsername());
        if (receiver != null && receiver.isOnline()) {
            userManager.forwardTransferPause(transferId, receiver.getUsername());
        }
    }
    
    private void handleResumeTransfer(String transferId) throws IOException {
        FileTransferRequest request = activeTransfers.get(transferId);
        if (request == null) {
            sendError("Transfer not found: " + transferId);
            return;
        }
        
        logger.info("Resuming transfer: " + transferId);
        
        send("RESUME_TRANSFER_ACK|" + transferId);
        
        User receiver = userManager.getUser(request.getReceiverUsername());
        if (receiver != null && receiver.isOnline()) {
            userManager.forwardTransferResume(transferId, receiver.getUsername());
        }
    }
    
    private void handleChunkCommand(String transferId, int chunkIndex, int totalChunks) throws IOException {
        FileTransferRequest request = activeTransfers.get(transferId);
        if (request == null) {
            sendError("Transfer not found: " + transferId);
            return;
        }
        
        logger.info("Handling chunk " + chunkIndex + "/" + totalChunks + " for transfer: " + transferId);
        
        try {
            Object chunkObj = in.readObject();
            if (!(chunkObj instanceof SecureMessage)) {
                sendError("Invalid chunk data format");
                return;
            }
            
            SecureMessage chunk = (SecureMessage) chunkObj;
            
            String receiverUsername = request.getReceiverUsername();
            
            userManager.sendToUser(receiverUsername, "CHUNK|" + transferId + "|" + chunkIndex + "|" + totalChunks);
            userManager.sendToUser(receiverUsername, chunk);
            
        } catch (ClassNotFoundException e) {
            logger.log(Level.WARNING, "Error reading chunk data", e);
            sendError("Error reading chunk data: " + e.getMessage());
        }
    }
    
    /**
     * Handle a signed chunk command - receive and forward signed chunks
     * Forwards signed chunks without verification (verification done by recipient)
     */
    private void handleSignedChunkCommand(String transferId, int chunkIndex, int totalChunks) throws IOException {
        try {
            
            logger.info("Handling signed chunk " + chunkIndex + "/" + totalChunks + " for transfer: " + transferId);
            LoggingManager.logTransfer(logger, transferId, "Relaying signed chunk", 
                "Chunk " + chunkIndex + " of " + totalChunks + " with digital signature");
            
            // Basic validation of chunk sequence parameters
            if (chunkIndex < 0 || chunkIndex >= totalChunks || totalChunks <= 0) {
                sendError("Invalid chunk sequence parameters");
                LoggingManager.logSecurity(logger, "SECURITY ERROR: Invalid chunk sequence parameters for transfer " + transferId + 
                                         " - index: " + chunkIndex + ", total: " + totalChunks);
                return;
            }
            
            Object chunkObj = in.readObject();
            if (!(chunkObj instanceof SignedSecureMessage)) {
                sendError("Invalid signed chunk data format - expected SignedSecureMessage");
                LoggingManager.logSecurity(logger, "SECURITY ERROR: Invalid signed chunk format received for transfer " + transferId);
                return;
            }
            
            SignedSecureMessage signedChunk = (SignedSecureMessage) chunkObj;
            
            if (!signedChunk.isValid()) {
                sendError("Invalid signed chunk structure");
                LoggingManager.logSecurity(logger, "SECURITY ERROR: Malformed SignedSecureMessage received for transfer " + transferId);
                return;
            }
            
            // Verify that the embedded sequence number in the nonce matches what was declared
            String nonce = signedChunk.getMessage().nonce;
            if (nonce != null && nonce.contains(":")) {
                try {
                    String[] nonceParts = nonce.split(":");
                    if (nonceParts.length >= 2) {
                        int embeddedChunkIndex = Integer.parseInt(nonceParts[1]);
                        if (embeddedChunkIndex != chunkIndex) {
                            LoggingManager.logSecurity(logger, "SECURITY ALERT: Chunk sequence mismatch in transfer " + transferId + 
                                                     ". Command claims: " + chunkIndex + ", Embedded in nonce: " + embeddedChunkIndex);
                            sendError("Security error: chunk sequence mismatch");
                            return;
                        }
                    }
                } catch (NumberFormatException e) {
                    // If we can't parse the sequence number, log it but proceed
                    LoggingManager.logSecurity(logger, "WARNING: Could not parse sequence number in nonce: " + nonce);
                }
            }
            
            FileTransferRequest transferRequest = activeTransfers.get(transferId);
            if (transferRequest == null) {
                sendError("Transfer not found: " + transferId);
                LoggingManager.logTransfer(logger, transferId, "Transfer lookup failed", "No active transfer found");
                return;
            }
            
            String recipientUsername = transferRequest.getReceiverUsername();
            try {
                userManager.sendToUser(recipientUsername, "SIGNED_CHUNK|" + transferId + "|" + chunkIndex + "|" + totalChunks);
                userManager.sendToUser(recipientUsername, signedChunk);
                
                LoggingManager.logTransfer(logger, transferId, "Signed chunk forwarded", 
                    "Chunk " + chunkIndex + " forwarded to " + recipientUsername);
            } catch (Exception e) {
                sendError("Failed to forward signed chunk to recipient");
                LoggingManager.logTransfer(logger, transferId, "Forward failed", 
                    "Could not forward signed chunk " + chunkIndex + ": " + e.getMessage());
            }
            
        } catch (ClassNotFoundException e) {
            sendError("Failed to read signed chunk data");
            logger.log(Level.WARNING, "Failed to read signed chunk for transfer: " + transferId, e);
            LoggingManager.logSecurity(logger, "SECURITY ERROR: Failed to deserialize signed chunk: " + e.getMessage());
        } catch (IOException e) {
            throw e;
        }
    }
    
    private void handleTransferComplete(String transferId) throws IOException {
        FileTransferRequest request = activeTransfers.get(transferId);
        if (request == null) {
            sendError("Transfer not found: " + transferId);
            return;
        }
        
        logger.info("Transfer complete: " + transferId);
        
        // Mark the transfer as complete for anti-replay protection
        CryptoUtils.markTransferComplete(transferId);
        
        String receiverUsername = request.getReceiverUsername();
        
        userManager.sendToUser(receiverUsername, "TRANSFER_COMPLETE|" + transferId);
        
        activeTransfers.remove(transferId);
    }
    
    private void handleAcceptTransfer(String transferId) throws IOException {
        FileTransferRequest request = activeTransfers.get(transferId);
        if (request == null) {
            sendError("Transfer not found: " + transferId);
            return;
        }
        
        logger.info("Transfer accepted by recipient: " + transferId);
        
        send("TRANSFER_ACCEPT_ACK|" + transferId);
        
        String senderUsername = request.getSenderUsername();
        userManager.forwardTransferAcceptance(transferId, senderUsername);
    }
    
    private void handleRejectTransfer(String transferId) throws IOException {
        FileTransferRequest request = activeTransfers.get(transferId);
        if (request == null) {
            sendError("Transfer not found: " + transferId);
            return;
        }
        
        logger.info("Transfer rejected by recipient: " + transferId);
        
        send("TRANSFER_REJECT_ACK|" + transferId);
        
        String senderUsername = request.getSenderUsername();
        userManager.forwardTransferRejection(transferId, senderUsername);
        
        activeTransfers.remove(transferId);
    }
    
    private void sendUsersList() throws IOException {
        List<User> users = userManager.getAllUsers();
        send(users);
    }
    
    public void send(Object message) throws IOException {
        synchronized (out) {
            out.writeObject(message);
            out.flush();
        }
    }
    
    private void sendError(String errorMessage) {
        try {
            send("ERROR|" + errorMessage);
        } catch (IOException e) {
            logger.log(Level.WARNING, "Error sending error message", e);
        }
    }
    
    private void cleanup() {
        try {
            if (currentUser != null) {
                userManager.removeConnection(currentUser.getUsername());
                
                if (currentSessionToken != null) {
                    sessionManager.removeSession(currentSessionToken);
                    LoggingManager.logSecurity(logger, "Session cleaned up for user: " + currentUser.getUsername());
                    currentSessionToken = null;
                }
                
                currentUser.setOnline(false);
                userManager.broadcastUserStatus(currentUser);
                
                logger.info("User " + currentUser.getUsername() + " is now offline");
            }
            
            if (clientIP != null) {
                rateLimitManager.releaseConnection(clientIP);
                logger.info("Released connection tracking for IP: " + clientIP);
            }
            
            if (in != null) in.close();
            if (out != null) out.close();
            if (clientSocket != null && !clientSocket.isClosed()) {
                clientSocket.close();
            }
        } catch (IOException e) {
            logger.log(Level.WARNING, "Error during cleanup", e);
        }
    }

    private void startSessionMonitoring() {
        Thread sessionMonitor = new Thread(() -> {
            while (running && currentSessionToken != null) {
                try {
                    Thread.sleep(5 * 60 * 1000); // Check every 5 minutes
                    
                    if (!validateSession()) {
                        LoggingManager.logSecurity(logger, "Session expired for user: " + 
                                                 (currentUser != null ? currentUser.getUsername() : "unknown"));
                        try {
                            send("SESSION_EXPIRED|Your session has expired. Please login again.");
                            Thread.sleep(1000); // Give time for message to be sent
                        } catch (IOException | InterruptedException e) {
                        }
                        running = false;
                        break;
                    }
                    
                    if (sessionManager.isSessionExpiringsoon(currentSessionToken)) {
                        try {
                            send("SESSION_WARNING|Your session will expire soon due to inactivity.");
                        } catch (IOException e) {
                            logger.warning("Failed to send session warning: " + e.getMessage());
                        }
                    }
                    
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        });
        sessionMonitor.setDaemon(true);
        sessionMonitor.setName("SessionMonitor-" + (currentUser != null ? currentUser.getUsername() : "unknown"));
        sessionMonitor.start();
    }
    
    private boolean validateSession() {
        if (currentSessionToken == null) {
            return false;
        }
        
        boolean valid = sessionManager.validateAndRefreshSession(currentSessionToken);
        
        if (!valid) {
            currentSessionToken = null;
            if (currentUser != null) {
                currentUser.setOnline(false);
                userManager.broadcastUserStatus(currentUser);
            }
        }
        
        return valid;
    }

    private boolean requireValidSession() {
        if (currentUser == null || currentSessionToken == null) {
            try {
                send("ERROR|Authentication required");
            } catch (IOException e) {
                logger.warning("Failed to send authentication error: " + e.getMessage());
            }
            return false;
        }
        
        if (!validateSession()) {
            try {
                send("SESSION_EXPIRED|Please login again");
            } catch (IOException e) {
                logger.warning("Failed to send session expired message: " + e.getMessage());
            }
            return false;
        }
        
        return true;
    }

    private void handleLogout() throws IOException {
        if (currentUser != null) {
            LoggingManager.logSecurity(logger, "User logging out: " + currentUser.getUsername());
            
            if (currentSessionToken != null) {
                sessionManager.removeSession(currentSessionToken);
                currentSessionToken = null;
            }
            
            currentUser.setOnline(false);
            userManager.broadcastUserStatus(currentUser);
            currentUser = null;
            
            send("LOGOUT_ACK");
        }
    }
}
