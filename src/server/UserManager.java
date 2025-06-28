package server;

import common.FileTransferRequest;
import common.User;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class UserManager {
    private static final Logger logger = Logger.getLogger(UserManager.class.getName());
    
    private final Map<String, User> users = new ConcurrentHashMap<>();
    
    private final Map<String, ServerConnectionHandler> connections = new ConcurrentHashMap<>();

    public void addUser(User user) {
        users.put(user.getUsername(), user);
    }

    public User getUser(String username) {
        return users.get(username);
    }
    
    public List<User> getAllUsers() {
        return new ArrayList<>(users.values());
    }

    public void registerConnection(String username, ServerConnectionHandler handler) {
        connections.put(username, handler);
        User user = users.get(username);
        if (user != null) {
            user.setOnline(true);
        }
    }

    public void removeConnection(String username) {
        connections.remove(username);
        User user = users.get(username);
        if (user != null) {
            user.setOnline(false);
        }
    }

    public void sendToUser(String username, Object message) {
        ServerConnectionHandler handler = connections.get(username);
        if (handler != null) {
            try {
                handler.send(message);
            } catch (IOException e) {
                logger.log(Level.WARNING, "Error sending message to user " + username, e);
                removeConnection(username);
            }
        }
    }

    public void broadcast(Object message) {
        for (Map.Entry<String, ServerConnectionHandler> entry : connections.entrySet()) {
            try {
                entry.getValue().send(message);
            } catch (IOException e) {
                logger.log(Level.WARNING, "Error broadcasting to user " + entry.getKey(), e);
                removeConnection(entry.getKey());
            }
        }
    }

    public void broadcastUserStatus(User user) {
        String statusMessage = "USER_STATUS|" + user.getUsername() + "|" + (user.isOnline() ? "online" : "offline");
        broadcast(statusMessage);
    }

    public void forwardFileTransferRequest(FileTransferRequest request, String transferId) {
        String recipient = request.getReceiverUsername();
        ServerConnectionHandler recipientHandler = connections.get(recipient);
        
        if (recipientHandler != null) {
            try {
                recipientHandler.send("TRANSFER_REQUEST|" + transferId + "|" + request.getSenderUsername() + 
                                     "|" + request.getFileName() + "|" + request.getFileSize());
                recipientHandler.send(request);
            } catch (IOException e) {
                logger.log(Level.WARNING, "Error forwarding transfer request to " + recipient, e);
            }
        } else {
            logger.warning("Recipient not connected: " + recipient);
        }
    }

    public void forwardTransferPause(String transferId, String username) {
        ServerConnectionHandler handler = connections.get(username);
        
        if (handler != null) {
            try {
                handler.send("PAUSE_TRANSFER|" + transferId);
            } catch (IOException e) {
                logger.log(Level.WARNING, "Error forwarding transfer pause to " + username, e);
            }
        } else {
            logger.warning("User not connected: " + username);
        }
    }

    public void forwardTransferResume(String transferId, String username) {
        ServerConnectionHandler handler = connections.get(username);
        
        if (handler != null) {
            try {
                handler.send("RESUME_TRANSFER|" + transferId);
            } catch (IOException e) {
                logger.log(Level.WARNING, "Error forwarding transfer resume to " + username, e);
            }
        } else {
            logger.warning("User not connected: " + username);
        }
    }
    
    public void forwardTransferAcceptance(String transferId, String senderUsername) {
        ServerConnectionHandler handler = connections.get(senderUsername);
        
        if (handler != null) {
            try {
                handler.send("TRANSFER_ACCEPTED|" + transferId);
                logger.info("Transfer acceptance forwarded to sender: " + senderUsername + " for transfer: " + transferId);
            } catch (IOException e) {
                logger.log(Level.WARNING, "Error forwarding transfer acceptance to " + senderUsername, e);
            }
        } else {
            logger.warning("Sender not connected: " + senderUsername);
        }
    }
    
    public void forwardTransferRejection(String transferId, String senderUsername) {
        ServerConnectionHandler handler = connections.get(senderUsername);
        
        if (handler != null) {
            try {
                handler.send("TRANSFER_REJECTED|" + transferId);
                logger.info("Transfer rejection forwarded to sender: " + senderUsername + " for transfer: " + transferId);
            } catch (IOException e) {
                logger.log(Level.WARNING, "Error forwarding transfer rejection to " + senderUsername, e);
            }
        } else {
            logger.warning("Sender not connected: " + senderUsername);
        }
    }
}
