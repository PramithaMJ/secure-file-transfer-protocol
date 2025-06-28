# Secure File Transfer Protocol
Buld with Java 11

**Step 1: Clean and create build directory (Windows PowerShell):**
```powershell
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
New-Item -ItemType Directory -Path "build"
```

**Step 2: Compile all Java files:**
```powershell
javac -d build -cp src src\common\*.java src\client\*.java src\server\*.java
``` project implements a secure file transfer protocol that ensures confidentiality, integrity, and protection against replay attacks. It uses a client-server architecture to support multiple users transferring files securely.

## Security Features

1. **Confidentiality**:

   - RSA encryption for key exchange
   - AES-256 encryption for file contents
   - CBC mode with random IV for each chunk
2. **Integrity**:

   - HMAC-SHA256 verification for each chunk
   - HMAC covers encrypted data, IV, timestamp, and nonce
3. **Authentication**:

   - Server authenticates clients via user accounts
   - Clients verify server responses
4. **Replay Protection**:

   - Unique nonce for each chunk
   - Timestamp validation
   - Server-side tracking of used nonces

## How to Build and Run

### Prerequisites

- Java Development Kit (JDK) 11 or higher
- Java Swing (included in JDK)

### Building the Project

Buld with Java 11

```bash
cd "/Secure file transfer protocol" && rm -rf build && mkdir -p build && javac -source 11 -target 11 -d build src/common/*.java src/client/*.java src/server/*.java
```

```bash
# Compile all Java files
cd "Secure file transfer protocol"
javac src/common/*.java src/server/*.java src/client/*.java -d build/
```

### Running the Server

```bash
# Start the server
cd "Secure file transfer protocol"
java -cp build server.Server
```

### Running the Client

```bash
# Start the client GUI
cd "Secure file transfer protocol"
java -cp build client.ClientUI
```
