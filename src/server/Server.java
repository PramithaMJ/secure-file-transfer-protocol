package server;

import common.*;
import java.io.*;
import java.net.*;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Server {
    private static final Logger logger = LoggingManager.getLogger(Server.class.getName());
    private int port;
    private ServerSocket serverSocket;
    private boolean running;
    private UserManager userManager;
    private SessionManager sessionManager;
    private RateLimitManager rateLimitManager;
    private DoSMonitor dosMonitor;
    private ExecutorService threadPool;
    
    public Server(int port) {
        this.port = port;
        this.userManager = new UserManager();
        this.sessionManager = new SessionManager();
        this.rateLimitManager = new RateLimitManager();
        this.dosMonitor = new DoSMonitor(rateLimitManager);
        this.threadPool = Executors.newCachedThreadPool();
    }
    
    public void start() {
        try {
            serverSocket = new ServerSocket(port);
            running = true;
            
            logger.info("Server started on port " + port + " with DoS protection enabled");
            
            while (running) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    String clientIP = clientSocket.getInetAddress().getHostAddress();
                    
                    if (rateLimitManager.isBlacklisted(clientIP)) {
                        logger.warning("Rejected connection from blacklisted IP: " + clientIP);
                        clientSocket.close();
                        continue;
                    }
                    
                    if (!rateLimitManager.allowConnection(clientIP)) {
                        logger.warning("Connection limit exceeded for IP: " + clientIP);
                        clientSocket.close();
                        continue;
                    }
                    
                    logger.info("New client connected: " + clientIP);
                    
                    ServerConnectionHandler handler = new ServerConnectionHandler(clientSocket, userManager, 
                                                                             sessionManager, rateLimitManager);
                    threadPool.execute(handler);
                } catch (IOException e) {
                    if (running) {
                        logger.log(Level.WARNING, "Error accepting client connection", e);
                    }
                }
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error starting server", e);
            System.err.println("Error starting server: " + e.getMessage());
        }
    }
    
    public void stop() {
        try {
            running = false;
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
            threadPool.shutdown();
            if (sessionManager != null) {
                sessionManager.shutdown();
            }
            if (dosMonitor != null) {
                dosMonitor.shutdown();
            }
            logger.info("Server stopped");
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error stopping server", e);
        }
    }

    public String getSecurityStatus() {
        if (dosMonitor != null) {
            return dosMonitor.getSecurityStatus();
        }
        return "DoS Monitor not initialized";
    }

    public common.RateLimitManager.RateLimitStats getRateLimitStats() {
        if (rateLimitManager != null) {
            return rateLimitManager.getStats();
        }
        return null;
    }
    
    public static void main(String[] args) {
        // Check if we should run the anti-replay tests
        if (args.length > 0 && args[0].equals("--test-replay-protection")) {
            logger.info("Running anti-replay protection tests...");
            ReplayTestUtils.runAntiReplayTests();
            return;
        }
        
        Properties props = new Properties();
        int port = 9999;

        try (InputStream input = new FileInputStream("resources/config.properties")) {
            props.load(input);
            port = Integer.parseInt(props.getProperty("server.port", "9999"));
        } catch (IOException e) {
            logger.info("Config file not found or cannot be read. Using default settings.");
        }
        
        Server server = new Server(port);
        
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("Shutting down server...");
            server.stop();
        }));
        
        server.start();
    }
}
