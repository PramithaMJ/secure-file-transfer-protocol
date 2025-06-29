package client;

import java.io.*;
import java.net.*;
import java.util.logging.*;

public class ClientConnectionHandler {
    private static final Logger logger = Logger.getLogger(ClientConnectionHandler.class.getName());
    
    private Socket socket;
    private ObjectOutputStream out;
    private ObjectInputStream in;
    private boolean connected = false;

    public void connect(String address, int port) throws IOException {
        socket = new Socket(address, port);
        out = new ObjectOutputStream(socket.getOutputStream());
        in = new ObjectInputStream(socket.getInputStream());
        connected = true;
    }

    public void listen(int port, int timeout) throws IOException {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            serverSocket.setSoTimeout(timeout);
            socket = serverSocket.accept();
            out = new ObjectOutputStream(socket.getOutputStream());
            in = new ObjectInputStream(socket.getInputStream());
            connected = true;
        }
    }
    
    public void send(Object obj) throws IOException {
        if (!connected) {
            throw new IOException("Not connected");
        }
        
        out.writeObject(obj);
        out.flush();
    }
    
    public Object receive() throws IOException, ClassNotFoundException {
        if (!connected) {
            throw new IOException("Not connected");
        }
        
        return in.readObject();
    }

    public void close() {
        try {
            connected = false;
            if (in != null) in.close();
            if (out != null) out.close();
            if (socket != null) socket.close();
        } catch (IOException e) {
            logger.log(Level.WARNING, "Error closing connection", e);
        }
    }

    public boolean isConnected() {
        return connected;
    }
}
