package client;

import common.*;
import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.io.*;
import java.util.*;
import java.util.List;
import java.util.logging.*;

public class ClientUI extends JFrame implements Client.ClientEventListener {
    private static final Logger logger = LoggingManager.getLogger(ClientUI.class.getName());
    
    private Client client;
    private String serverAddress = "localhost";
    private int serverPort = 9999;
    
    private JTextField usernameField;
    private JButton loginButton;
    private JButton logoutButton;
    private JList<User> userList;
    private DefaultListModel<User> userListModel;
    private JButton refreshButton;
    private JButton sendFileButton;
    private JButton pauseTransferButton;
    private JButton resumeTransferButton;
    private JTextArea logArea;
    private JProgressBar transferProgress;
    private JLabel statusLabel;
    
    private Map<String, String> activeTransfers = new HashMap<>();
    
    private String currentTransferId;
    
    public ClientUI() {
        setTitle("Secure File Transfer Client");
        setSize(800, 600);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        
        initComponents();
        initActions();
        
        updateStatus("Ready");
        
        client = new Client(serverAddress, serverPort);
        client.setEventListener(this);
        
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            if (client != null && client.isConnected()) {
                client.disconnect();
            }
        }));
    }
    
    private void initComponents() {
        setLayout(new BorderLayout(5, 5));
        
        JPanel topPanel = createConnectionPanel();
        
        JSplitPane centerPanel = createCenterPanel();
        
        JPanel bottomPanel = createLogPanel();
        
        add(topPanel, BorderLayout.NORTH);
        add(centerPanel, BorderLayout.CENTER);
        add(bottomPanel, BorderLayout.SOUTH);
    }
    
    private JPanel createConnectionPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        JPanel loginPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        JLabel userLabel = new JLabel("Username:");
        usernameField = new JTextField(15);
        loginButton = new JButton("Login");
        logoutButton = new JButton("Logout");
        logoutButton.setEnabled(false);
        
        loginPanel.add(userLabel);
        loginPanel.add(usernameField);
        loginPanel.add(loginButton);
        loginPanel.add(logoutButton);
        
        panel.add(loginPanel, BorderLayout.WEST);
        
        statusLabel = new JLabel("Not connected");
        statusLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 10));
        panel.add(statusLabel, BorderLayout.EAST);
        
        return panel;
    }
    
    private JSplitPane createCenterPanel() {
        JPanel usersPanel = new JPanel(new BorderLayout(5, 5));
        usersPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Online Users", TitledBorder.LEFT, TitledBorder.TOP));
        
        userListModel = new DefaultListModel<>();
        userList = new JList<>(userListModel);
        userList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane userScrollPane = new JScrollPane(userList);
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        refreshButton = new JButton("Refresh");
        sendFileButton = new JButton("Send File");
        sendFileButton.setEnabled(false);
        
        buttonPanel.add(refreshButton);
        buttonPanel.add(sendFileButton);
        
        usersPanel.add(userScrollPane, BorderLayout.CENTER);
        usersPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        JTabbedPane rightTabs = new JTabbedPane();
        
        JPanel transfersPanel = new JPanel(new BorderLayout(5, 5));
        transferProgress = new JProgressBar(0, 100);
        transferProgress.setStringPainted(true);
        transferProgress.setString("No active transfers");
        transfersPanel.add(transferProgress, BorderLayout.NORTH);
        
        JPanel transferControlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        pauseTransferButton = new JButton("Pause");
        resumeTransferButton = new JButton("Resume");
        pauseTransferButton.setEnabled(false);
        resumeTransferButton.setEnabled(false);
        transferControlPanel.add(pauseTransferButton);
        transferControlPanel.add(resumeTransferButton);
        transfersPanel.add(transferControlPanel, BorderLayout.SOUTH);
        
        rightTabs.addTab("Current Transfer", transfersPanel);
        rightTabs.addTab("Transfer History", new JPanel());
        
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, usersPanel, rightTabs);
        splitPane.setDividerLocation(300);
        return splitPane;
    }
    
    private JPanel createLogPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Log", TitledBorder.LEFT, TitledBorder.TOP));
        
        logArea = new JTextArea();
        logArea.setEditable(false);
        
        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setPreferredSize(new Dimension(750, 150));
        
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private void initActions() {
        loginButton.addActionListener(e -> login());
        logoutButton.addActionListener(e -> logout());
        refreshButton.addActionListener(e -> refreshUserList());
        sendFileButton.addActionListener(e -> sendFile());
        pauseTransferButton.addActionListener(e -> pauseCurrentTransfer());
        resumeTransferButton.addActionListener(e -> resumeCurrentTransfer());

        userList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                User selectedUser = userList.getSelectedValue();
                sendFileButton.setEnabled(selectedUser != null && 
                                         selectedUser.isOnline() && 
                                         client.isConnected() &&
                                         !selectedUser.getUsername().equals(client.getCurrentUser().getUsername()));
            }
        });
    }
    
    private void login() {
        String username = usernameField.getText().trim();
        if (username.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a username", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        try {
            updateStatus("Connecting...");
            boolean success = client.login(username);
            
            if (success) {
                loginButton.setEnabled(false);
                usernameField.setEnabled(false);
                logoutButton.setEnabled(true);
                refreshButton.setEnabled(true);
                updateStatus("Connected as " + username);
                log("Logged in successfully as " + username);
                
                TransferHistory history = new TransferHistory(username);
                TransferHistoryPanel historyPanel = new TransferHistoryPanel(history, client);
                
                Component comp = ((JSplitPane)getContentPane().getComponent(1)).getRightComponent();
                if (comp instanceof JTabbedPane) {
                    JTabbedPane tabs = (JTabbedPane)comp;
                    tabs.setComponentAt(1, historyPanel);
                }
                
                refreshUserList();
            } else {
                updateStatus("Login failed");
                log("Login failed");
            }
        } catch (Exception ex) {
            updateStatus("Connection error");
            log("Error connecting to server: " + ex.getMessage());
            logger.log(Level.SEVERE, "Error during login", ex);
        }
    }
    
    private void logout() {
        client.logout();
        client.disconnect();
        
        loginButton.setEnabled(true);
        usernameField.setEnabled(true);
        logoutButton.setEnabled(false);
        refreshButton.setEnabled(false);
        sendFileButton.setEnabled(false);
        userListModel.clear();
        
        updateStatus("Disconnected");
        log("Logged out");
        
        client = new Client(serverAddress, serverPort);
        client.setEventListener(this);
    }
    
    private void refreshUserList() {
        if (client.isConnected()) {
            List<User> users = client.getUserList();
            updateUserList(users);
        }
    }
    
    private void sendFile() {
        User recipient = userList.getSelectedValue();
        if (recipient == null) {
            return;
        }
        
        JFileChooser fileChooser = new JFileChooser();
        int result = fileChooser.showOpenDialog(this);
        
        if (result == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            String filePath = file.getAbsolutePath();
            
            new Thread(() -> {
                try {
                    updateStatus("Initiating file transfer...");
                    boolean initiated = client.initiateFileTransfer(recipient.getUsername(), filePath);
                    
                    if (initiated) {
                        log("File transfer initiated: " + file.getName() + " to " + recipient.getUsername());
                    } else {
                        updateStatus("File transfer failed");
                        log("Failed to initiate file transfer");
                    }
                } catch (Exception e) {
                    updateStatus("Error during file transfer");
                    log("Error during file transfer: " + e.getMessage());
                    logger.log(Level.SEVERE, "Error during file transfer", e);
                }
            }).start();
        }
    }
    
    private void updateUserList(List<User> users) {
        SwingUtilities.invokeLater(() -> {
            userListModel.clear();
            
            User currentUser = client.getCurrentUser();
            for (User user : users) {
                if (currentUser != null && !user.getUsername().equals(currentUser.getUsername())) {
                    userListModel.addElement(user);
                }
            }
            
            userList.repaint();
        });
    }
    
    private void updateStatus(String status) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText(status);
        });
    }
    
    private void log(String message) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }
        
    @Override
    public void onUserListUpdated(List<User> users) {
        updateUserList(users);
    }
    
    @Override
    public void onUserStatusChange(String username, boolean online) {
        log("User " + username + " is now " + (online ? "online" : "offline"));
        refreshUserList();
    }
    
    @Override
    public void onFileTransferRequest(String transferId, FileTransferRequest request) {
        SwingUtilities.invokeLater(() -> {
            String sender = request.getSenderUsername();
            String fileName = request.getFileName();
            long fileSize = request.getFileSize();
            
            int choice = JOptionPane.showConfirmDialog(
                this,
                sender + " wants to send you file: " + fileName + " (" + fileSize + " bytes)\nAccept?",
                "File Transfer Request",
                JOptionPane.YES_NO_OPTION
            );
            
            if (choice == JOptionPane.YES_OPTION) {
                log("Accepted file transfer from " + sender + ": " + fileName);
                if (client != null) {
                    client.sendAcceptTransfer(transferId);
                    refreshTransferHistoryPanel();
                }
            } else {
                log("Rejected file transfer from " + sender);
                if (client != null) {
                    client.sendRejectTransfer(transferId);
                }
            }
        });
    }
    
    @Override
    public void onTransferProgress(String transferId, int progress) {
        SwingUtilities.invokeLater(() -> {
            String fileName = activeTransfers.get(transferId);
            transferProgress.setValue(progress);
            transferProgress.setString(fileName + ": " + progress + "%");
            
            currentTransferId = transferId;
            pauseTransferButton.setEnabled(true);
            resumeTransferButton.setEnabled(false);
        });
    }
    
    @Override
    public void onTransferComplete(String transferId) {
        SwingUtilities.invokeLater(() -> {
            String fileName = activeTransfers.remove(transferId);
            
            if (fileName == null && client != null) {
                TransferHistory history = client.getTransferHistory();
                if (history != null) {
                    TransferRecord record = history.getTransfer(transferId);
                    if (record != null) {
                        fileName = record.getFileName() + " (" + 
                                  (record.getSenderUsername().equals(client.getCurrentUser().getUsername()) ?
                                   "to " + record.getReceiverUsername() :
                                   "from " + record.getSenderUsername()) + ")";
                    } else {
                        // No transfer record found
                    }
                } else {
                    // Transfer history is null
                }
            }
            
            if (fileName == null) {
                fileName = "unknown file";
            }
            
            log("File transfer completed: " + fileName);
            updateStatus("File transfer completed");
            transferProgress.setValue(0);
            transferProgress.setString("Transfer complete");
            
            refreshTransferHistoryPanel();
            
            javax.swing.Timer timer1 = new javax.swing.Timer(100, e -> {
                refreshTransferHistoryPanel();
                ((javax.swing.Timer) e.getSource()).stop();
            });
            timer1.start();
            
            javax.swing.Timer timer2 = new javax.swing.Timer(300, e -> {
                refreshTransferHistoryPanel();
                ((javax.swing.Timer) e.getSource()).stop();
            });
            timer2.start();
        });
    }
    
    @Override
    public void onTransferError(String transferId, String error) {
        SwingUtilities.invokeLater(() -> {
            String fileName = activeTransfers.get(transferId);
            log("Error in file transfer " + (fileName != null ? fileName : transferId) + ": " + error);
            updateStatus("File transfer error");
        });
    }
    
    @Override
    public void onDisconnect() {
        SwingUtilities.invokeLater(() -> {
            log("Disconnected from server");
            updateStatus("Disconnected");
            loginButton.setEnabled(true);
            usernameField.setEnabled(true);
            logoutButton.setEnabled(false);
            refreshButton.setEnabled(false);
            sendFileButton.setEnabled(false);
        });
    }
    
    @Override
    public void onError(String error) {
        SwingUtilities.invokeLater(() -> {
            log("Error: " + error);
            updateStatus("Error: " + error);
        });
    }
    
    @Override
    public void onTransferPaused(String transferId) {
        SwingUtilities.invokeLater(() -> {
            String fileName = activeTransfers.get(transferId);
            log("Transfer paused: " + fileName);
            updateStatus("Transfer paused");
            pauseTransferButton.setEnabled(false);
            resumeTransferButton.setEnabled(true);
        });
    }
    
    @Override
    public void onTransferResumed(String transferId) {
        SwingUtilities.invokeLater(() -> {
            String fileName = activeTransfers.get(transferId);
            log("Transfer resumed: " + fileName);
            updateStatus("Transfer resumed");
            pauseTransferButton.setEnabled(true);
            resumeTransferButton.setEnabled(false);
        });
    }
    
    @Override
    public void onTransferStarting(String transferId, String fileName) {
        SwingUtilities.invokeLater(() -> {
            activeTransfers.put(transferId, fileName);
            transferProgress.setValue(0);
            transferProgress.setString("Starting transfer: " + fileName);
            log("Starting file transfer: " + fileName);
            refreshTransferHistoryPanel();
        });
    }
    
    private void pauseCurrentTransfer() {
        if (currentTransferId != null) {
            if (client.pauseTransfer(currentTransferId)) {
                log("Pausing transfer: " + activeTransfers.get(currentTransferId));
                pauseTransferButton.setEnabled(false);
                resumeTransferButton.setEnabled(true);
            } else {
                log("Failed to pause transfer");
            }
        }
    }
    
    private void resumeCurrentTransfer() {
        if (currentTransferId != null) {
            if (client.resumeTransfer(currentTransferId)) {
                log("Resuming transfer: " + activeTransfers.get(currentTransferId));
                pauseTransferButton.setEnabled(true);
                resumeTransferButton.setEnabled(false);
            } else {
                log("Failed to resume transfer");
            }
        }
    }
    
    private void refreshTransferHistoryPanel() {
        if (client != null && client.isConnected()) {
            TransferHistory history = client.getTransferHistory();
            if (history != null) {
                history.reloadHistory();
                
                try {
                    Thread.sleep(50);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            
            TransferHistoryPanel historyPanel = findTransferHistoryPanel(this);
            if (historyPanel != null) {
                historyPanel.refresh();
                
                historyPanel.repaint();
                historyPanel.revalidate();
                
                this.repaint();
                this.revalidate();
            } else {
                // TransferHistoryPanel not found
            }
        } else {
            // Client is null or not connected
        }
    }
    
    private TransferHistoryPanel findTransferHistoryPanel(Container container) {
        for (Component comp : container.getComponents()) {
            if (comp instanceof TransferHistoryPanel) {
                return (TransferHistoryPanel) comp;
            } else if (comp instanceof Container) {
                TransferHistoryPanel result = findTransferHistoryPanel((Container) comp);
                if (result != null) {
                    return result;
                }
            }
        }
        return null;
    }
    
    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        LoggingManager.initialize();
        Logger logger = LoggingManager.getLogger(ClientUI.class.getName());
        logger.info("Starting Secure File Transfer Client application");
        
        SwingUtilities.invokeLater(() -> {
            ClientUI ui = new ClientUI();
            ui.setVisible(true);
            logger.info("Client UI initialized and displayed");
        });
    }
}
