# Secure File Transfer Protocol

This project implements a secure file transfer protocol that ensures confidentiality, integrity, and protection against replay attacks. It uses a client-server architecture to support multiple users transferring files securely.

## Java Version Requirement

**Important:** This application requires Java 17 or higher to run.

## Quick Start (macOS/Linux)

**Build the project:**
```bash
cd "Secure file transfer protocol"
rm -rf build
mkdir -p build
javac -d build src/common/*.java src/client/*.java src/server/*.java
```

**Run the server:**
```bash
java -cp build server.Server
```

**Run the client:**
```bash
java -cp build client.ClientUI
```
project implements a secure file transfer protocol that ensures confidentiality, integrity, and protection against replay attacks. It uses a client-server architecture to support multiple users transferring files securely.


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

4. **Anti-Replay Protection**:
   - Unique nonce for each chunk
   - Timestamp validation (5-minute window)
   - Server-side tracking of used nonces
   - Automatic cleanup of old nonces

5. **Path Traversal Protection**:
   - Filename validation and sanitization
   - Secure file path creation
   - Prevention of directory traversal attacks

6. **Public Key Validation**:
   - Minimum RSA 2048-bit key strength enforcement
   - Algorithm validation (RSA-only)
   - Key fingerprint generation for verification
   - Comprehensive input validation
   - Prevention of key spoofing attacks

7. **Digital Signatures**:
   - SHA256withRSA digital signatures for authentication
   - Non-repudiation: cryptographic proof of sender identity
   - Message integrity verification via signature
   - Protection against forgery and impersonation attacks
   - End-to-end authentication (sender to recipient)


## How to Build and Run

### Prerequisites

- Java Development Kit (JDK) 17 or higher
- Java Swing (included in JDK)

### Detailed Build Instructions

#### macOS/Linux

```bash
# Clean and create build directory
cd "Secure file transfer protocol"
rm -rf build
mkdir -p build

# Compile all Java files to build directory
javac -d build src/common/*.java src/client/*.java src/server/*.java
```

#### Windows

```powershell
# Clean and create build directory
cd "Secure file transfer protocol"
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
New-Item -ItemType Directory -Path "build"

# Compile all Java files to build directory
javac -d build src\common\*.java src\client\*.java src\server\*.java
```

### Running the Application

#### Running the Server

```bash
# Start the server
cd "Secure file transfer protocol"
java -cp build server.Server
```

#### Running the Client

```bash
# Start the client GUI
cd "Secure file transfer protocol"
java -cp build client.ClientUI
```

### Troubleshooting

If you encounter an error about unsupported class version:

```
java.lang.UnsupportedClassVersionError: server/Server has been compiled by a more recent version of the Java Runtime
```

This means you're trying to run the application with an older Java version. Make sure to use Java 17 or higher:

```bash
# Check your Java version
java -version

# If using multiple Java versions, specify path to Java 17:
/path/to/java17/bin/java -cp build server.Server
```
