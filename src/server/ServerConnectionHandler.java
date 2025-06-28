package server;

import common.*;
import common.SecureMessage;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ServerConnectionHandler implements Runnable {
    private static final Logger logger = Logger.getLogger(ServerConnectionHandler.class.getName());
    
    private Socket clientSocket;
    private ObjectInputStream in;
    private ObjectOutputStream out;
    private UserManager userManager;
    private User currentUser;
    private boolean running;
    
    private static final Map<String, FileTransferRequest> activeTransfers = new HashMap<>();
    
    public ServerConnectionHandler(Socket clientSocket, UserManager userManager) {
        this.clientSocket = clientSocket;
        this.userManager = userManager;
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
                if (currentUser != null) {
                    currentUser.setOnline(false);
                    userManager.broadcastUserStatus(currentUser);
                    currentUser = null;
                    send("LOGOUT_ACK");
                }
                break;
                
            case "GET_USERS":
                sendUsersList();
                break;
                
            case "DISCONNECT":
                running = false;
                break;
                
            case "PAUSE_TRANSFER":
                if (parts.length >= 2) {
                    String transferId = parts[1];
                    handlePauseTransfer(transferId);
                }
                break;
                
            case "RESUME_TRANSFER":
                if (parts.length >= 2) {
                    String transferId = parts[1];
                    handleResumeTransfer(transferId);
                }
                break;
                
            case "CHUNK":
                if (parts.length >= 4) {
                    String transferId = parts[1];
                    int chunkIndex = Integer.parseInt(parts[2]);
                    int totalChunks = Integer.parseInt(parts[3]);
                    handleChunkCommand(transferId, chunkIndex, totalChunks);
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
        
        User existingUser = userManager.getUser(username);
        
        if (existingUser == null) {
            userManager.addUser(user);
            currentUser = user;
            currentUser.setOnline(true);
            logger.info("New user registered: " + username);
            send("REGISTER_SUCCESS|" + username);
        } else {
            currentUser = existingUser;
            currentUser.setOnline(true);
            logger.info("User logged in: " + username);
            send("LOGIN_SUCCESS|" + username);
        }
        
        userManager.registerConnection(username, this);
        
        userManager.broadcastUserStatus(currentUser);
        
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
        
        // Send acknowledgment to the recipient
        send("TRANSFER_ACCEPT_ACK|" + transferId);
        
        // Forward acceptance to the sender
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
                
                currentUser.setOnline(false);
                
                userManager.broadcastUserStatus(currentUser);
                
                logger.info("User " + currentUser.getUsername() + " is now offline");
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
}
