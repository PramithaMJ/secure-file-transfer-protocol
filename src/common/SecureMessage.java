package common;

import java.io.*;

public class SecureMessage implements Serializable {
    private static final long serialVersionUID = 1L;
    
    public byte[] encryptedData;
    public byte[] mac;
    public byte[] iv;
    public long timestamp;
    public String nonce;

    public SecureMessage(byte[] encryptedData, byte[] mac, byte[] iv, long timestamp, String nonce) {
        this.encryptedData = encryptedData;
        this.mac = mac;
        this.iv = iv;
        this.timestamp = timestamp;
        this.nonce = nonce;
    }

    public byte[] serialize() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        dos.writeInt(encryptedData.length);
        dos.write(encryptedData);
        dos.writeInt(mac.length);
        dos.write(mac);
        dos.writeInt(iv.length);
        dos.write(iv);
        dos.writeLong(timestamp);
        dos.writeUTF(nonce);

        return baos.toByteArray();
    }

    public static SecureMessage deserialize(byte[] data) throws IOException {
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        DataInputStream dis = new DataInputStream(bais);

        int encLen = dis.readInt();
        byte[] encryptedData = new byte[encLen];
        dis.readFully(encryptedData);

        int macLen = dis.readInt();
        byte[] mac = new byte[macLen];
        dis.readFully(mac);

        int ivLen = dis.readInt();
        byte[] iv = new byte[ivLen];
        dis.readFully(iv);

        long timestamp = dis.readLong();
        String nonce = dis.readUTF();

        return new SecureMessage(encryptedData, mac, iv, timestamp, nonce);
    }
}
