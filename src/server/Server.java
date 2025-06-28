package server;

import java.io.*;
import java.net.*;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Server {
    private static final Logger logger = Logger.getLogger(Server.class.getName());
    private int port;
    private ServerSocket serverSocket;
    private boolean running;
    private UserManager userManager;
    private ExecutorService threadPool;
    
    public Server(int port) {
        this.port = port;
        this.userManager = new UserManager();
        this.threadPool = Executors.newCachedThreadPool();
    }
    
    public void start() {
        try {
            serverSocket = new ServerSocket(port);
            running = true;
            
            logger.info("Server started on port " + port);
            
            while (running) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    logger.info("New client connected: " + clientSocket.getInetAddress());
                    
                    ServerConnectionHandler handler = new ServerConnectionHandler(clientSocket, userManager);
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
            logger.info("Server stopped");
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error stopping server", e);
        }
    }
    
    public static void main(String[] args) {
        Properties props = new Properties();
        int port = 9999;

        try (InputStream input = new FileInputStream("resources/config.properties")) {
            props.load(input);
            port = Integer.parseInt(props.getProperty("server.port", "9999"));
        } catch (IOException e) {
            logger.info("Config file not found or cannot be read. Using default settings.");
        }
        
        Server server = new Server(port);
        server.start();
        
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("Shutting down server...");
            server.stop();
        }));
    }
}
