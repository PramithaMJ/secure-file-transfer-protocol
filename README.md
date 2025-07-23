# Secure File Transfer Protocol with Perfect Forward Secrecy

[![Build](https://github.com/PramithaMJ/secure-file-transfer-protocol/actions/workflows/build.yml/badge.svg)](https://github.com/PramithaMJ/secure-file-transfer-protocol/actions/workflows/build.yml)
[![Security Rating](https://img.shields.io/badge/security-A%2B-brightgreen)](http://157.230.40.190:9000/dashboard?id=Pramitha)
[![PFS Enabled](https://img.shields.io/badge/PFS-Enabled-blue)](docs/PFS_INTERACTIVE_DEMO.md)
[![Code Quality](https://img.shields.io/badge/quality-enterprise%20grade-success)](docs/COMPREHENSIVE_SECURITY_REPORT.md)

![Security Demo](https://img.shields.io/badge/🎥_Watch-Security_Demo-red?style=for-the-badge)

This project implements a secure file transfer protocol with **Perfect Forward Secrecy (PFS)** that ensures confidentiality, integrity, authentication, and protection against sophisticated attacks. It uses a client-server-client relay architecture with ephemeral Diffie-Hellman key exchange to support multiple users transferring files with enterprise-level security.

## Key Features

**Perfect Forward Secrecy (PFS)** - Ephemeral Diffie-Hellman key exchange
**Military-Grade Encryption** - AES-256-CBC with unique keys per transfer
**Digital Signatures** - SHA256withRSA for authentication & non-repudiation
**Anti-Replay Protection** - Unique nonces with timestamp validation
**MITM Attack Prevention** - Authenticated key exchange with digital signatures
**DoS Protection** - Multi-tier rate limiting and IP blacklisting
**Real-Time Security Monitoring** - Automated threat detection & response
**Enterprise Compliance** - NIST/NSA approved cryptographic standards

## Security Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                CLIENT-SERVER-CLIENT RELAY ARCHITECTURE              │
│                     with Perfect Forward Secrecy                    │
└─────────────────────────────────────────────────────────────────────┘

Alice (Sender)              Server (Relay)              Bob (Receiver)
┌─────────────┐              ┌─────────────┐              ┌─────────────┐
│ RSA-2048    │              │   SESSION   │              │ RSA-2048    │
│ Long-term   │◄─────────────►│ MANAGEMENT  │◄─────────────►│ Long-term │
│ Key Pair    │              │ & SECURITY  │              │ Key Pair    │
└─────────────┘              └─────────────┘              └─────────────┘
       │                            │                            │
┌─────────────┐                     │                     ┌─────────────┐
│ Ephemeral   │                     │                     │ Ephemeral   │
│ DH Keys     │◄────────AUTHENTICATED RELAY───────────────►│ DH Keys    │
│ (2048-bit)  │                     │                     │ (2048-bit)  │
└─────────────┘                     │                     └─────────────┘
       │                            │                            │
       └──────────────── SHARED SECRET K = g^(ab) mod p ────────────────┘
                              │
                    ┌─────────────────┐
                    │ AES-256 Session │
                    │ Key = HKDF(K)   │
                    └─────────────────┘
```

## Cryptographic Specifications


| **Security Component**     | **Algorithm**        | **Key Size** | **Security Level** |
| -------------------------- | -------------------- | ------------ | ------------------ |
| **Asymmetric Encryption**  | RSA-OAEP-SHA256      | 2048-bit     | 112-bit equivalent |
| **Symmetric Encryption**   | AES-256-CBC          | 256-bit      | 256-bit            |
| **Message Authentication** | HMAC-SHA256          | 256-bit      | 256-bit            |
| **Digital Signatures**     | SHA256withRSA        | 2048-bit     | 112-bit equivalent |
| **Key Exchange**           | Diffie-Hellman (PFS) | 2048-bit     | 112-bit equivalent |
| **Hash Functions**         | SHA-256              | N/A          | 256-bit            |

** Security Compliance:** NIST SP 800-57, FIPS 140-2, NSA Suite B Compatible

## Directory Structure

Directory structure:

```
└──secure-file-transfer-protocol/
    ├── README.md
    ├── build.bat
    ├── build.sh
    ├── sonar-project.properties
    ├── data/
    │   ├── Alice_transfer_history.dat
    │   └── Bob_transfer_history.dat
    ├── docs/
    │   ├── [Update]Security Flow Architecture.drawio
    │   ├── architecture.xml
    │   └── Security Flow Architecture.drawio
    ├── resources/
    │   ├── config.properties
    │   └── logging.properties
    ├── src/
    │   ├── client/
    │   │   ├── Client.java
    │   │   ├── ClientConnectionHandler.java
    │   │   ├── ClientUI.java
    │   │   ├── TransferHistory.java
    │   │   └── TransferHistoryPanel.java
    │   ├── common/
    │   │   ├── CryptoUtils.java
    │   │   ├── FileTransferRequest.java
    │   │   ├── LoggingManager.java
    │   │   ├── Participant.java
    │   │   ├── RateLimitManager.java
    │   │   ├── ReplayTestUtils.java
    │   │   ├── SecureMessage.java
    │   │   ├── Session.java
    │   │   ├── SessionManager.java
    │   │   ├── SignedSecureMessage.java
    │   │   ├── TransferRecord.java
    │   │   └── User.java
    │   └── server/
    │       ├── DoSMonitor.java
    │       ├── Server.java
    │       ├── ServerConnectionHandler.java
    │       └── UserManager.java
    ├── .github/
    │   └── workflows/
    │       └── build.yml
    └── .scannerwork/
        └── .sonar_lock
```

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

## Security Demo Videos & Documentation

### **Live Demo Video**

[![Security Demo](https://img.shields.io/badge/🎥_Watch-Security_Demo-red?style=for-the-badge)](https://youtu.be/0arjgfnfygI)

### **Comprehensive Security Documentation**

- **[ Alice & Bob Security Demo](docs/ALICE_BOB_SECURITY_DEMO_CODEBASE.md)** - Complete walkthrough with code references
- **[ Perfect Forward Secrecy Demo](docs/PFS_INTERACTIVE_DEMO.md)** - PFS implementation details
- **[ Attack Prevention Analysis](docs/ATTACK_PREVENTION_DEMO.md)** - Real attack scenarios & defenses
- **[ Comprehensive Security Report](docs/COMPREHENSIVE_SECURITY_REPORT.md)** - Enterprise security analysis
- **[ Visual Security Guide](docs/VISUAL_SECURITY_GUIDE.md)** - Security flow diagrams

### *Advanced Security Features

Based on your codebase, here's the updated security features section with specific code references:

## Security Features

### **Confidentiality**

- **RSA Encryption for Key Exchange**: `CryptoUtils.RSA_TRANSFORMATION` = `"RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING"`
- **AES-256 Encryption for File Contents**: `CryptoUtils.AES_KEY_SIZE` = `256`
- **CBC Mode with Random IV**: `CryptoUtils.AES_TRANSFORMATION` = `"AES/CBC/PKCS5Padding"`
- **Secure IV Generation**: `CryptoUtils.encryptChunk()` - `SecureRandom.getInstanceStrong().nextBytes(iv)`

### **Integrity**

- **HMAC-SHA256 Verification**: `CryptoUtils.HMAC_ALGORITHM` = `"HmacSHA256"`
- **Comprehensive MAC Coverage**: `CryptoUtils.encryptChunk()` - HMAC over encrypted data + IV + timestamp + nonce + chunk index
- **Timing-Safe Comparison**: `CryptoUtils.verifyIntegrity()` - `MessageDigest.isEqual()` prevents timing attacks

### **Authentication**

- **Digital Signatures**: `CryptoUtils.SIGNATURE_ALGORITHM` = `"SHA256withRSA"`
- **Signature Creation**: `CryptoUtils.signData()` - Cryptographic proof of sender identity
- **Signature Verification**: `CryptoUtils.verifySignature()` - Detects forgery and tampering
- **Signed Message Processing**: `Client.receiveSignedFileChunk()` - End-to-end authentication

### **Perfect Forward Secrecy (PFS)**

- **Ephemeral DH Key Generation**: `CryptoUtils.generateEphemeralDHKeyPair()` - New keys for each transfer
- **DH Shared Secret**: `CryptoUtils.generateDHSharedSecret()` - Computational secrecy
- **Key Derivation**: `CryptoUtils.deriveAESKeyFromSecret()` - HKDF-based key expansion
- **DH Key Exchange in Transfer**: `Client.initiateFileTransfer()` - Ephemeral key pair generation and signature

### **Anti-Replay Protection**

- **Unique Nonce Generation**: `CryptoUtils.generateSecureNonce()` - 16 bytes of cryptographically secure randomness
- **Sequence Number Tracking**: `CryptoUtils.validateSequenceOnly()` - Detects duplicate and out-of-order chunks
- **Timestamp Validation**: `CryptoUtils.verifyIntegrity()` - 5-minute window with clock skew tolerance
- **Nonce Tracking Maps**: `CryptoUtils.usedNonces` and `CryptoUtils.transferSequences`

### **DoS Attack Protection**

- **Rate Limiting**: `RateLimitManager.checkRateLimit()` - IP-based request throttling
- **DoS Monitoring**: `DoSMonitor.performSecurityCheck()` - Real-time threat detection
- **Connection Management**: `Server.handleConnection()` - Thread pool with limits
- **Memory Management**: `CryptoUtils.cleanupOldNonces()` - Automatic cleanup of tracking data

### **Public Key Validation**

- **Key Strength Validation**: `CryptoUtils.validatePublicKey()` - Minimum 2048-bit RSA enforcement
- **Algorithm Verification**: `CryptoUtils.bytesToPublicKey()` - RSA-only validation
- **Key Fingerprinting**: `CryptoUtils.generateKeyFingerprint()` - SHA-256 fingerprint generation
- **Client-Side Validation**: `Client.initiateFileTransfer()` - Pre-transfer key verification

### **Secure Message Processing**

- **Signed Message Creation**: `CryptoUtils.signMessage()` - Digital signature wrapper
- **Message Structure Validation**: `SignedSecureMessage.isValid()` - Input validation
- **Chunk Transfer Security**: `Client.sendFileData()` - Signed chunk transmission
- **Integrity Verification Flow**: `Client.receiveFileChunk()` - Multi-layer security checks

### **Memory Security**

- **Secure Key Wiping**: `CryptoUtils.secureWipe()` - Memory cleanup after use
- **Bounded Memory Usage**: `CryptoUtils.MAX_NONCE_CACHE_SIZE` - Prevents memory exhaustion
- **Automatic Cleanup**: `CryptoUtils.cleanupExecutor` - Scheduled nonce cleanup
- **Resource Management**: `CryptoUtils.shutdown()` - Proper cleanup on shutdown

### **Sequence Integrity**

- **Chunk Sequencing**: `CryptoUtils.encryptChunk()` - Embedded sequence numbers
- **Order Validation**: `CryptoUtils.validateSequenceOrder()` - Detects gaps and reordering
- **Transfer Completion**: `CryptoUtils.markTransferComplete()` - Cleanup after transfer
- **Client-Side Validation**: `Client.receiveFileChunk()` - Sequence mismatch detection

### **Diagnostic and Monitoring**

- **Security Logging**: `LoggingManager.logSecurity()` - Comprehensive security event tracking
- **Diagnostic Tools**: `CryptoUtils.getDiagnosticInfo()` - Signature verification troubleshooting
- **Replay Testing**: `ReplayTestUtils` - Anti-replay system validation
- **Transfer Monitoring**: `LoggingManager.logTransfer()` - File transfer event logging

## Security Achievements & Compliance

### **Security Standards Compliance**

**NIST SP 800-57** - Cryptographic key management compliance
**FIPS 140-2** - Federal security requirements
**NSA Suite B** - High-security algorithm compatibility
**RFC 3526** - Diffie-Hellman group parameters
**RFC 5246** - TLS 1.2 cryptographic standards

### **Attack Resistance Matrix**


| **Attack Vector**     | **Protection Method**    | **Implementation**                  | **Status**    |
| --------------------- | ------------------------ | ----------------------------------- | ------------- |
| **Man-in-the-Middle** | Digital Signatures       | `CryptoUtils.verifySignature()`     | **Blocked**   |
| **Replay Attacks**    | Nonce + Timestamp        | `CryptoUtils.verifyIntegrity()`     | **Blocked**   |
| **Data Tampering**    | HMAC-SHA256              | `Mac.getInstance("HmacSHA256")`     | **Detected**  |
| **Key Compromise**    | Perfect Forward Secrecy  | `generateEphemeralDHKeyPair()`      | **Protected** |
| **DoS Attacks**       | Rate Limiting            | `RateLimitManager.checkRateLimit()` | **Mitigated** |
| **Eavesdropping**     | AES-256 Encryption       | `AES/CBC/PKCS5Padding`              | **Prevented** |
| **Identity Spoofing** | PKI Authentication       | `validatePublicKey()`               | **Verified**  |
| **Timing Attacks**    | Constant-Time Comparison | `MessageDigest.isEqual()`           | **Resistant** |

### **Security Metrics**

- **Encryption Strength**: 256-bit AES (Military Grade)
- **Key Exchange Security**: 2048-bit DH (112-bit equivalent)
- **Signature Strength**: 2048-bit RSA (112-bit equivalent)
- **Hash Security**: SHA-256 (256-bit)
- **Session Security**: Perfect Forward Secrecy enabled
- **Attack Detection**: Real-time monitoring
- **Memory Security**: Secure key wiping implemented

### **Enterprise Features**

**Zero-Knowledge Architecture** - Server never sees plaintext
**Multi-User Support** - Concurrent secure sessions
**Audit Trail** - Complete security event logging
**Scalable Design** - Thread-pool based architecture
**Cross-Platform** - Java 17+ compatibility
**Production Ready** - Comprehensive error handling

### **Support & Contact**

For security questions, vulnerability reports, or enterprise licensing:

- **GitHub Issues**: [Report Security Issues](https://github.com/PramithaMJ/secure-file-transfer-protocol/issues)
- **Documentation**: See `docs/` folder for detailed security analysis
