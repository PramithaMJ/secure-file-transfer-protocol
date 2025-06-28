# 🚀 How to Run the Secure File Transfer Application

## ✅ **All files are now compiled and stored in the `build/` folder**

### **Directory Structure:**
```
build/
├── common/           # Core cryptographic and utility classes
├── client/           # Client application classes  
└── server/           # Server application classes
```

## 🏃‍♂️ **Running the Application**

### **Step 1: Start the Server**
Open **Terminal 1** and run:
```powershell
cd "c:\Users\LPram\OneDrive\Desktop\ACADEMIC\Academic 7 Sem\Information Security\IS-Project\secure-file-transfer-protocol"
java -cp build server.Server
```

**Expected Output:**
```
Loaded logging configuration from ...
2025-06-29 XX:XX:XX.XXX INFO [server.Server main] Secure File Transfer Server starting...
2025-06-29 XX:XX:XX.XXX INFO [server.Server main] Server listening on port: 9999
2025-06-29 XX:XX:XX.XXX INFO [common.LoggingManager logSecurity] [SECURITY] Server started and listening for connections
```

### **Step 2: Start Client 1**
Open **Terminal 2** and run:
```powershell
cd "c:\Users\LPram\OneDrive\Desktop\ACADEMIC\Academic 7 Sem\Information Security\IS-Project\secure-file-transfer-protocol"
java -cp build client.ClientUI
```

### **Step 3: Start Client 2** 
Open **Terminal 3** and run:
```powershell
cd "c:\Users\LPram\OneDrive\Desktop\ACADEMIC\Academic 7 Sem\Information Security\IS-Project\secure-file-transfer-protocol"
java -cp build client.ClientUI
```

## 🧪 **Testing Anti-Replay Protection**
To test the security fixes:
```powershell
cd "c:\Users\LPram\OneDrive\Desktop\ACADEMIC\Academic 7 Sem\Information Security\IS-Project\secure-file-transfer-protocol"
java -cp build common.AntiReplayTest
```

## 📋 **Usage Instructions**

### **1. Login Process:**
- Server starts on port 9999
- Client GUIs will open
- Enter username and password (any values work for demo)
- Click "Connect & Login"

### **2. File Transfer:**
- Both clients must be logged in
- Select recipient from dropdown
- Choose file to transfer
- Click "Send File"
- Recipient will get acceptance dialog
- File transfers with encryption

### **3. Transfer History:**
- View sent/received files in history panel
- **Now updates immediately** (fixed transfer history bug!)
- Filter by "All Transfers", "Sent", or "Received"

## 🔒 **Security Features (Now Working):**
- ✅ **Anti-replay protection** - Messages cannot be replayed
- ✅ **Timestamp validation** - Old messages (5+ minutes) rejected
- ✅ **Nonce tracking** - Duplicate nonces detected and blocked
- ✅ **Cryptographically secure encryption** - AES-256 + RSA-2048
- ✅ **HMAC integrity verification** - Tamper detection
- ✅ **Secure random generation** - Strong nonces and IVs

## 🛑 **Important Notes:**

### **Run Order:**
1. **ALWAYS start Server first**
2. Then start Client instances
3. Server must remain running for clients to work

### **Stopping the Application:**
- Close client windows normally
- Stop server with `Ctrl+C` in terminal
- Resources are automatically cleaned up

### **File Locations:**
- **Downloaded files:** `downloads/` folder
- **Transfer history:** `data/` folder  
- **Logs:** `logs/` folder
- **Configuration:** `resources/` folder

## 🔧 **Troubleshooting:**

### **"Address already in use" error:**
- Another instance is already running
- Kill existing processes: `taskkill /f /im java.exe`
- Or change port in Server.java

### **"Class not found" error:**
- Make sure you're in the project root directory
- Verify `build/` folder contains compiled classes
- Recompile if needed: `javac -d build -cp src src\common\*.java src\client\*.java src\server\*.java`

### **Connection failed:**
- Ensure server is running first
- Check server logs for errors
- Verify port 9999 is not blocked by firewall

## ✅ **Ready to Use!**
The secure file transfer application is now compiled and ready to run with full anti-replay protection!
