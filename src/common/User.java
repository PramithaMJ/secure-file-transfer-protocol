package common;

import java.io.Serializable;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class User extends Participant implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private String username;
    private boolean online;
    
    public User(String username) throws NoSuchAlgorithmException {
        super();
        this.username = username;
        this.online = false;
    }
    
    public User(String username, byte[] publicKeyBytes) throws NoSuchAlgorithmException {
        super(publicKeyBytes);
        this.username = username;
        this.online = false;
    }
    
    public String getUsername() {
        return username;
    }
    
    public boolean isOnline() {
        return online;
    }
    
    public void setOnline(boolean online) {
        this.online = online;
    }
    
    @Override
    public PublicKey getPublicKey() {
        return super.getPublicKey();
    }
    
    @Override
    public String toString() {
        return username + (online ? " (online)" : " (offline)");
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        User user = (User) obj;
        return username.equals(user.username);
    }
    
    @Override
    public int hashCode() {
        return username.hashCode();
    }
}
