package client;

import common.TransferRecord;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.text.SimpleDateFormat;
import java.util.List;

public class TransferHistoryPanel extends JPanel {
    private TransferHistory transferHistory;
    private Client client;
    private JTable historyTable;
    private DefaultTableModel tableModel;
    private JButton refreshButton;
    private JButton openFileButton;
    private JButton openFolderButton;
    private JButton pauseTransferButton;
    private JButton resumeTransferButton;
    private JTabbedPane tabPane;
    
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    
    public TransferHistoryPanel(TransferHistory transferHistory) {
        this(transferHistory, null);
    }
    
    public TransferHistoryPanel(TransferHistory transferHistory, Client client) {
        this.transferHistory = transferHistory;
        this.client = client;
        
        setLayout(new BorderLayout(5, 5));
        
        String[] columns = {"File Name", "Sender", "Receiver", "Size (KB)", "Start Time", "Status", "Duration"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        historyTable = new JTable(tableModel);
        historyTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        historyTable.getTableHeader().setReorderingAllowed(false);
        
        tabPane = new JTabbedPane();
        tabPane.addTab("All Transfers", new JScrollPane(historyTable));
        tabPane.addTab("Sent", new JScrollPane());
        tabPane.addTab("Received", new JScrollPane());
        tabPane.addTab("Active", new JScrollPane());
        
        tabPane.addChangeListener(e -> refreshTable());
        
        JPanel buttonsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        refreshButton = new JButton("Refresh");
        openFileButton = new JButton("Open File");
        openFolderButton = new JButton("Open Folder");
        pauseTransferButton = new JButton("Pause Transfer");
        resumeTransferButton = new JButton("Resume Transfer");
        
        pauseTransferButton.setEnabled(false);
        resumeTransferButton.setEnabled(false);
        
        buttonsPanel.add(refreshButton);
        buttonsPanel.add(openFileButton);
        buttonsPanel.add(openFolderButton);
        buttonsPanel.add(pauseTransferButton);
        buttonsPanel.add(resumeTransferButton);
        
        add(tabPane, BorderLayout.CENTER);
        add(buttonsPanel, BorderLayout.SOUTH);
        
        initActions();
        
        refreshTable();
    }
    
    private void initActions() {
        refreshButton.addActionListener(e -> refreshTable());
        
        historyTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateButtonStates();
            }
        });
        
        openFileButton.addActionListener(e -> {
            int row = historyTable.getSelectedRow();
            if (row >= 0) {
                TransferRecord record = getSelectedRecord();
                if (record != null && record.getFilePath() != null) {
                    try {
                        Desktop.getDesktop().open(new File(record.getFilePath()));
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(this, 
                            "Could not open file: " + ex.getMessage(),
                            "Error", JOptionPane.ERROR_MESSAGE);
                    }
                } else {
                    JOptionPane.showMessageDialog(this, 
                        "No file path available for this transfer",
                        "Information", JOptionPane.INFORMATION_MESSAGE);
                }
            }
        });
        
        openFolderButton.addActionListener(e -> {
            int row = historyTable.getSelectedRow();
            if (row >= 0) {
                TransferRecord record = getSelectedRecord();
                if (record != null && record.getFilePath() != null) {
                    try {
                        File file = new File(record.getFilePath());
                        Desktop.getDesktop().open(file.getParentFile());
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(this, 
                            "Could not open folder: " + ex.getMessage(),
                            "Error", JOptionPane.ERROR_MESSAGE);
                    }
                } else {
                    JOptionPane.showMessageDialog(this, 
                        "No file path available for this transfer",
                        "Information", JOptionPane.INFORMATION_MESSAGE);
                }
            }
        });
        
        pauseTransferButton.addActionListener(e -> {
            if (client == null) {
                JOptionPane.showMessageDialog(this, 
                    "Client not initialized",
                    "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            TransferRecord record = getSelectedRecord();
            if (record != null && record.getStatus() == TransferRecord.TransferStatus.IN_PROGRESS) {
                boolean success = client.pauseTransfer(record.getTransferId());
                if (!success) {
                    JOptionPane.showMessageDialog(this, 
                        "Failed to pause transfer",
                        "Error", JOptionPane.ERROR_MESSAGE);
                }
            } else {
                JOptionPane.showMessageDialog(this, 
                    "No active transfer selected",
                    "Information", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        
        resumeTransferButton.addActionListener(e -> {
            if (client == null) {
                JOptionPane.showMessageDialog(this, 
                    "Client not initialized",
                    "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            TransferRecord record = getSelectedRecord();
            if (record != null && record.getStatus() == TransferRecord.TransferStatus.PAUSED) {
                boolean success = client.resumeTransfer(record.getTransferId());
                if (!success) {
                    JOptionPane.showMessageDialog(this, 
                        "Failed to resume transfer",
                        "Error", JOptionPane.ERROR_MESSAGE);
                }
            } else {
                JOptionPane.showMessageDialog(this, 
                    "No paused transfer selected",
                    "Information", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        
        historyTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = historyTable.getSelectedRow();
                    if (row >= 0) {
                        showTransferDetails(getSelectedRecord());
                    }
                }
            }
        });
    }
    
    private TransferRecord getSelectedRecord() {
        int row = historyTable.getSelectedRow();
        if (row < 0) return null;
        
        int tabIndex = tabPane.getSelectedIndex();
        List<TransferRecord> records;
        
        switch (tabIndex) {
            case 1: records = transferHistory.getSentTransfers(); break;
            case 2: records = transferHistory.getReceivedTransfers(); break;
            case 3: records = transferHistory.getActiveTransfers(); break;
            default: records = transferHistory.getAllTransfers(); break;
        }
        
        if (row < records.size()) {
            return records.get(row);
        }
        
        return null;
    }
    
    private void refreshTable() {
        tableModel.setRowCount(0);
        
        List<TransferRecord> records;
        int tabIndex = tabPane.getSelectedIndex();
        
        switch (tabIndex) {
            case 1: records = transferHistory.getSentTransfers(); break;
            case 2: records = transferHistory.getReceivedTransfers(); break;
            case 3: records = transferHistory.getActiveTransfers(); break;
            default: records = transferHistory.getAllTransfers(); break;
        }
        
        for (TransferRecord record : records) {
            Object[] row = new Object[7];
            row[0] = record.getFileName();
            row[1] = record.getSenderUsername();
            row[2] = record.getReceiverUsername();
            row[3] = String.format("%.2f", record.getFileSize() / 1024.0);
            row[4] = DATE_FORMAT.format(record.getStartTime());
            row[5] = record.getStatus();
            
            long durationMs = record.getDuration();
            long seconds = durationMs / 1000;
            long minutes = seconds / 60;
            seconds %= 60;
            row[6] = minutes + "m " + seconds + "s";
            
            tableModel.addRow(row);
        }
        
        updateButtonStates();
    }
    
    private void updateButtonStates() {
        TransferRecord record = getSelectedRecord();
        boolean hasSelection = record != null;
        
        openFileButton.setEnabled(hasSelection && record != null && record.getFilePath() != null);
        openFolderButton.setEnabled(hasSelection && record != null && record.getFilePath() != null);
        
        pauseTransferButton.setEnabled(hasSelection && record != null && 
                                      record.getStatus() == TransferRecord.TransferStatus.IN_PROGRESS &&
                                      client != null);
        
        resumeTransferButton.setEnabled(hasSelection && record != null && 
                                      record.getStatus() == TransferRecord.TransferStatus.PAUSED &&
                                      client != null);
    }
    
    private void showTransferDetails(TransferRecord record) {
        if (record == null) return;
        
        StringBuilder details = new StringBuilder();
        details.append("Transfer ID: ").append(record.getTransferId()).append("\n");
        details.append("File: ").append(record.getFileName()).append("\n");
        details.append("Size: ").append(String.format("%.2f KB", record.getFileSize() / 1024.0)).append("\n");
        details.append("From: ").append(record.getSenderUsername()).append("\n");
        details.append("To: ").append(record.getReceiverUsername()).append("\n");
        details.append("Started: ").append(DATE_FORMAT.format(record.getStartTime())).append("\n");
        
        if (record.getCompletionTime() != null) {
            details.append("Completed: ").append(DATE_FORMAT.format(record.getCompletionTime())).append("\n");
        }
        
        details.append("Status: ").append(record.getStatus()).append("\n");
        details.append("Duration: ");
        long durationMs = record.getDuration();
        long seconds = durationMs / 1000;
        long minutes = seconds / 60;
        seconds %= 60;
        details.append(minutes).append("m ").append(seconds).append("s").append("\n");
        
        if (record.getFilePath() != null) {
            details.append("Location: ").append(record.getFilePath());
        }
        
        JOptionPane.showMessageDialog(this, details.toString(), 
            "Transfer Details", JOptionPane.INFORMATION_MESSAGE);
    }
}
