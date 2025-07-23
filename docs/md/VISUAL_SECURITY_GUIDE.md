# Visual Security Implementation Guide

## Step-by-Step Alice & Bob Client-Server-Client File Transfer Security

This document provides a complete visual walkthrough of how security is implemented in the protocol, showing exactly how Alice (client/sender) securely sends files to Bob (client/receiver) through a central server relay and how each attack is prevented.

---

## Characters & Setup

```
Alice (Client/Sender)
• Role: Corporate employee (client application)
• Goal: Send confidential_report.pdf to Bob through server
• Security concern: File contains sensitive data
• Long-term key: RSA-2048 key pair for authentication
• Connection: TCP socket to central server

Bob (Client/Receiver)  
• Role: Department manager (client application)
• Goal: Receive file securely through server
• Security concern: Verify authenticity and integrity
• Long-term key: RSA-2048 key pair for authentication  
• Connection: TCP socket to central server

Server (Relay Hub)
• Role: Central communication relay and security enforcer
• Goal: Securely route messages between Alice and Bob
• Security responsibility: Authentication, DoS prevention, logging
• Long-term key: RSA-2048 key pair for server authentication
• Architecture: Multi-threaded connection handler

Trudy (External Attacker)
• Role: Malicious network observer/active attacker
• Goal: Steal, modify, or disrupt client communications
• Capabilities: Network access, computing power, MITM attempts
• Limitations: Cannot break strong cryptography, blocked by server security
```

---

## Complete Security Flow Visualization

### Phase 1: Client Authentication to Server

```
Alice's Computer                     Central Server                    Bob's Computer
┌─────────────────────┐           ┌─────────────────────┐          ┌─────────────────────┐
│  1. Alice starts   │           │                     │          │  1. Bob starts      │
│     client app      │           │   Listening for     │          │     client app      │
│   ClientUI.java     │           │   connections...    │          │   ClientUI.java     │
│                     │           │                     │          │                     │
│  Username: Alice    │           │    Server.java      │          │  Username: Bob      │
│  Server: localhost  │           │   Port: 8080        │          │  Server: localhost  │
└─────────────────────┘           └─────────────────────┘          └─────────────────────┘
         │                                  │                                │
         │ 2. TCP Connection Request        │                                │
         │─────────────────────────────────►│                                │
         │                                  │                                │
         │                                  │ 3. DoS Protection Check        │
         │                                  │ ┌────────────────────────────┐ │
         │                                  │ │ RateLimitManager.java:     │ │
         │                                  │ │ • Check IP blacklist       │ │
         │                                  │ │ • Verify connection limit  │ │
         │                                  │ │ • Rate limit validation    │ │
         │                                  │ └────────────────────────────┘ │
         │                                  │                                │
         │ 4. Connection Accepted           │                                │
         │◄─────────────────────────────────│                                │
         │                                  │                                │
         │ 5. User Login                    │                                │
         │ USER_LOGIN{                      │                                │
         │   username: "Alice",             │                                │
         │   publicKey: RSA_Public_Alice    │                                │
         │ }                                │                                │
         │─────────────────────────────────►│                                │
         │                                  │                                │
         │                                  │ 6. Authentication Process      │
         │                                  │ ┌────────────────────────────┐ │
         │                                  │ │ ServerConnectionHandler:   │ │
         │                                  │ │ • Validate public key      │ │
         │                                  │ │ • Check key strength       │ │
         │                                  │ │ • Create user account      │ │
         │                                  │ │ • Generate session token   │ │
         │                                  │ └────────────────────────────┘ │
         │                                  │                                │
         │ 7. Login Success                 │                                │
         │ LOGIN_SUCCESS{                   │                                │
         │   sessionToken: "a1b2c3d4..."    │                                │
         │ }                                │                                │
         │◄─────────────────────────────────│                                │
         │                                  │                                │
         │                                  │                   8. Bob Login │
         │                                  │◄───────────────────────────────│
         │                                  │ (Same process as Alice)        │
         │                                  │                                │
         │                                  │ 9. Bob Login Success           │
         │                                  │───────────────────────────────►│
```

### Phase 2: Perfect Forward Secrecy Setup (Client-Server-Client)

```
Alice (Client)                  Server (Relay)                  Bob (Client)
┌─────────────────────┐           ┌─────────────────────┐          ┌─────────────────────┐
│ 10. File Transfer   │           │                     │          │                     │
│     Initiation      │           │                     │          │ Waiting for         │
│                     │           │                     │          │ transfers...        │
│    Select File:     │           │                     │          │                     │
│    confidential     │           │                     │          │                     │
│    _report.pdf      │           │                     │          │                     │
│    Send to: Bob     │           │                     │          │                     │
└─────────────────────┘           └─────────────────────┘          └─────────────────────┘
         │                                  │                                │
         │ 11. Generate Ephemeral DH Keys   │                                │
         │ ┌─────────────────────────────────┐                               │
         │ │ Client.java:                    │                               │
         │ │ KeyPair dhKeyPair =             │                               │
         │ │   CryptoUtils.generateEphemeral │                               │
         │ │   DHKeyPair();                  │                               │
         │ │                                 │                               │
         │ │ Private: a = random(2048-bit)   │ ← Secret! Never transmitted   │
         │ │ Public:  g^a mod p              │ ← Will be sent                │
         │ └─────────────────────────────────┘                               │
         │                                  │                                │
         │ 12. Sign DH Public Key           │                                │
         │ ┌─────────────────────────────────┐                               │
         │ │ byte[] signature =              │                               │
         │ │   CryptoUtils.signData(         │                               │
         │ │     dhPublicKey,                │                               │
         │ │     alice.getPrivateKey()       │                               │
         │ │   );                            │                               │
         │ └─────────────────────────────────┘                               │
         │                                  │                                │
         │ 13. Send File Transfer Request   │                                │
         │ FileTransferRequest{             │                                │
         │   sender: "Alice",               │                                │
         │   receiver: "Bob",               │                                │
         │   filename: "confidential_report.pdf",  │                         │
         │   senderDHPublicKey: g^a,        │                                │
         │   senderDHSignature: Sign(g^a)   │                                │
         │ }                                │                                │
         │─────────────────────────────────►│                                │
         │                                  │                                │
         │                                  │ 14. Server Relays to Bob       │
         │                                  │ FileTransferRequest{           │
         │                                  │   sender: "Alice",             │
         │                                  │   filename: "confidential_report.pdf", │
         │                                  │   senderDHPublicKey: g^a,      │
         │                                  │   senderDHSignature: Sign(g^a) │
         │                                  │ }                              │
         │                                  │──────────────────────────────►│
         │                                  │                                │
         │                                  │                                │ 15. Bob Verifies Alice's Signature
         │                                  │                                │ ┌─────────────────────────────┐
         │                                  │                                │ │ boolean valid =             │
         │                                  │                                │ │   CryptoUtils.verifySignature(│
         │                                  │                                │ │     dhPublicKey,            │
         │                                  │                                │ │     signature,              │
         │                                  │                                │ │     alicePublicKey          │
         │                                  │                                │ │   );                        │
         │                                  │                                │ │ if (!valid) {               │
         │                                  │                                │ │   // MITM attack detected!  │
         │                                  │                                │ │   reject();                 │
         │                                  │                                │ │ }                           │
         │                                  │                                │ └─────────────────────────────┘
         │                                  │                                │
         │                                  │                                │ 16. Bob DH Key Generation
         │                                  │                                │ ┌─────────────────────────────┐
         │                                  │                                │ │ KeyPair bobDH =             │
         │                                  │                                │ │   CryptoUtils.generateEphemeral│
         │                                  │                                │ │   DHKeyPair();              │
         │                                  │                                │ │                             │
         │                                  │                                │ │ Private: b = random(2048-bit)│ ← Bob's Secret!
         │                                  │                                │ │ Public:  g^b mod p          │ ← Will send
         │                                  │                                │ └─────────────────────────────┘
         │                                  │                                │
         │                                  │                                │ 17. Sign Bob's DH Key
         │                                  │                                │ ┌─────────────────────────────┐
         │                                  │                                │ │ byte[] bobSignature =       │
         │                                  │                                │ │   CryptoUtils.signData(     │
         │                                  │                                │ │     bobDHPublicKey,         │
         │                                  │                                │ │     bob.getPrivateKey()     │
         │                                  │                                │ │   );                        │
         │                                  │                                │ └─────────────────────────────┘
         │                                  │                                │
         │                                  │ 18. Bob Response to Server     │
         │                                  │ FileTransferResponse{          │
         │                                  │   transferId: "xyz123",        │
         │                                  │   receiverDHPublicKey: g^b,    │
         │                                  │   receiverDHSignature: Sign(g^b)│
         │                                  │ }                              │
         │                                  │◄──────────────────────────────│
         │                                  │                                │
         │ 19. Server Relays to Alice       │                                │
         │ FileTransferResponse{            │                                │
         │   transferId: "xyz123",          │                                │
         │   receiverDHPublicKey: g^b,      │                                │
         │   receiverDHSignature: Sign(g^b) │                                │
         │ }                                │                                │
         │◄─────────────────────────────────│                                │
         │                                  │                                │
         │ 20. Verify Bob's Signature       │                                │
         │ ┌─────────────────────────────────┐                               │
         │ │ boolean valid =                 │                               │
         │ │   CryptoUtils.verifySignature(  │                               │
         │ │     bobDHPublicKey,             │                               │
         │ │     bobSignature,               │                               │
         │ │     bobPublicKey                │                               │
         │ │   );                            │                               │
         │ │ if (!valid) {                   │                               │
         │ │   // MITM attack detected!      │                               │
         │ │   abort();                      │                               │
         │ │ }                               │                               │
         │ └─────────────────────────────────┘                               │
```

### Phase 3: Client-to-Client Shared Secret Computation & Key Derivation

```
Alice (Client)                  Server (Relay)                  Bob (Client)
┌─────────────────────┐           ┌─────────────────────┐          ┌─────────────────────┐
│ 21. Compute Shared  │           │                     │          │ 21. Compute Shared  │
│     Secret with Bob │           │  Server does NOT    │          │     Secret with Alice│
│                     │           │  compute or store   │          │                     │
│ SharedSecret =      │           │  the shared secret  │          │ SharedSecret =      │
│   (g^b)^a mod p     │           │                     │          │   (g^a)^b mod p     │
│ = g^(ab) mod p      │           │  Server only relays │          │ = g^(ab) mod p      │
│                     │           │  public keys        │          │                     │
│  Mathematical:      │           │                     │          │  Mathematical:      │
│ CryptoUtils.        │           │                     │          │ CryptoUtils.        │
│ generateDHShared    │           │                     │          │ generateDHShared    │
│ Secret(a, g^b)      │           │                     │          │ Secret(b, g^a)      │
└─────────────────────┘           └─────────────────────┘          └─────────────────────┘
         │                                  │                                │
         │ 22. Derive AES Key               │                                │ 22. Derive AES Key
         │ ┌─────────────────────────────────┐                               │ ┌─────────────────────────────┐
         │ │ SecretKey aesKey =              │                               │ │ SecretKey aesKey =          │
         │ │   CryptoUtils.deriveAESKey      │                               │ │   CryptoUtils.deriveAESKey  │
         │ │   FromSecret(sharedSecret);     │                               │ │   FromSecret(sharedSecret); │
         │ │                                 │                               │ │                             │
         │ │ // SHA-256(SharedSecret)        │                               │ │ // SHA-256(SharedSecret)    │
         │ │ AES_Key = SHA256(g^(ab) mod p)  │                               │ │ AES_Key = SHA256(g^(ab))    │
         │ └─────────────────────────────────┘                               │ └─────────────────────────────┘
         │                                  │                                │
         │ 23. Secure Memory Wipe           │                                │ 23. Secure Memory Wipe
         │ ┌─────────────────────────────────┐                               │ ┌─────────────────────────────┐
         │ │  SecureWipe(sharedSecret)       │                               │ │  SecureWipe(sharedSecret)   │
         │ │  SecureWipe(privateKey_a)       │                               │ │  SecureWipe(privateKey_b)   │
         │ │                                 │                               │ │                             │
         │ │ // Critical for PFS!            │                               │ │ // Critical for PFS!        │
         │ │ // Past sessions now secure     │                               │ │ // Past sessions secure     │
         │ │ // even if long-term keys       │                               │ │ // even if keys compromised │
         │ │ // are compromised later        │                               │ │                             │
         │ └─────────────────────────────────┘                               │ └─────────────────────────────┘
```

### Phase 4: Secure File Transmission Through Server Relay

```
Alice (Client)                  Server (Relay)                  Bob (Client)
┌─────────────────────┐           ┌─────────────────────┐          ┌─────────────────────┐
│ 24. File Chunking   │           │                     │          │                     │
│     & Encryption    │           │   Relay chunks      │          │ Waiting for         │
│                     │           │   with integrity    │          │ file chunks...      │
│ FOR each 4KB chunk: │           │   verification      │          │                     │
│                     │           │                     │          │                     │
│  Generate unique    │           │                     │          │                     │
│    IV per chunk     │           │                     │          │                     │
│  Create nonce:      │           │                     │          │                     │
│    "xyz123:0:time"  │           │                     │          │                     │
│  AES-256 encrypt    │           │                     │          │                     │
│  HMAC-SHA256        │           │                     │          │                     │
│  Digital sign       │           │                     │          │                     │
└─────────────────────┘           └─────────────────────┘          └─────────────────────┘
         │                                  │                                │
         │ 25. Send Signed Encrypted Chunk  │                                │
         │ SIGNED_CHUNK|xyz123|0|3          │                                │
         │ SignedSecureMessage{             │                                │
         │   secureMessage: {               │                                │
         │     encryptedData: "a7f9b2c8...",│                                │
         │     mac: "d3e1f4a7...",          │                                │
         │     iv: "1a2b3c4d...",           │                                │
         │     timestamp: 1640995200,       │                                │
         │     nonce: "xyz123:0:1640995200" │ ← Anti-replay protection       │
         │   },                             │                                │
         │   signature: "9b5c2e8f...",      │ ← Authentication               │
         │   senderUsername: "Alice"        │                                │
         │ }                                │                                │
         │─────────────────────────────────►│                                │
         │                                  │                                │
         │                                  │ 26. Server Relay Verification  │
         │                                  │ ┌─────────────────────────────┐ │
         │                                  │ │ // Verify sender signature   │ │
         │                                  │ │ boolean sigValid =          │ │
         │                                  │ │   CryptoUtils.verifySignature(│ │
         │                                  │ │     messageData, signature, │ │
         │                                  │ │     alicePublicKey);        │ │
         │                                  │ │                             │ │
         │                                  │ │ // Check replay protection  │ │
         │                                  │ │   checkNonceUniqueness(nonce);  │ │
         │                                  │ │                             │ │
         │                                  │ │ // Forward if valid         │ │
         │                                  │ └─────────────────────────────┘ │
         │                                  │                                │
         │                                  │ 27. Server Relays to Bob       │
         │                                  │ SIGNED_CHUNK|xyz123|0|3        │
         │                                  │ SignedSecureMessage{...}       │
         │                                  │───────────────────────────────►│
         │                                  │                                │
         │                                  │                                │ 28. Bob's Multi-Layer Verification
         │                                  │                                │ ┌─────────────────────────────┐
         │                                  │                                │ │ // Layer 1: Verify Alice's  │
         │                                  │                                │ │ //          signature       │
         │                                  │                                │ │ // Layer 2: Check replay    │
         │                                  │                                │ │ //          protection      │
         │                                  │                                │ │ // Layer 3: Verify HMAC     │
         │                                  │                                │ │ //          with shared key │
         │                                  │                                │ └─────────────────────────────┘
         │                                  │                                │
         │                                  │                                │ 29. Bob Decrypts Chunk
         │                                  │                                │ ┌─────────────────────────────┐
         │                                  │                                │ │ byte[] plaintext =          │
         │                                  │                                │ │   AES.decrypt(              │
         │                                  │                                │ │     encryptedData,          │
         │                                  │                                │ │     aesKey, iv);            │
         │                                  │                                │ └─────────────────────────────┘
         │                                  │                                │
         │                                  │ 30. Bob Chunk Acknowledgment   │
         │                                  │ CHUNK_ACK|xyz123|0             │
         │                                  │◄───────────────────────────────│
         │                                  │                                │
         │ 31. Server Relays ACK to Alice   │                                │
         │ CHUNK_ACK|xyz123|0               │                                │
         │◄─────────────────────────────────│                                │
         │                                  │                                │
         │ [Repeat for remaining chunks]    │                                │
```

### Phase 5: Transfer Completion & Security Cleanup

```
Alice (Client)                  Server (Relay)                  Bob (Client)
┌─────────────────────┐           ┌─────────────────────┐          ┌─────────────────────┐
│ 32. All chunks sent │           │                     │          │ 32. File received   │
│     to server       │           │                     │          │     completely      │
│                     │           │                     │          │                     │
│ Transfer complete!  │           │                     │          │  confidential       │
│                     │           │                     │          │    _report.pdf      │
│                     │           │                     │          │  All security       │
│                     │           │                     │          │    checks passed    │
└─────────────────────┘           └─────────────────────┘          └─────────────────────┘
         │                                  │                                │
         │ 33. Transfer Complete Signal     │                                │
         │ TRANSFER_COMPLETE|xyz123         │                                │
         │─────────────────────────────────►│                                │
         │                                  │                                │
         │                                  │ 34. Server Relays to Bob       │
         │                                  │ TRANSFER_COMPLETE|xyz123       │
         │                                  │───────────────────────────────►│
         │                                  │                                │
         │                                  │ 35. Server Security Cleanup    │
         │                                  │ ┌─────────────────────────────┐ │
         │                                  │ │ CryptoUtils.markTransfer    │ │
         │                                  │ │   Complete("xyz123");       │ │
         │                                  │ │                             │ │
         │                                  │ │ // Schedule cleanup:        │ │
         │                                  │ │ • Remove sequence tracking  │ │
         │                                  │ │ • Clear nonce cache        │ │
         │                                  │ │ • Update security stats    │ │
         │                                  │ │ • Log completion event     │ │
         │                                  │ └─────────────────────────────┘ │
         │                                  │                                │
         │ 36. Alice Memory Cleanup         │                                │ 36. Bob Memory Cleanup
         │ ┌─────────────────────────────────┐                               │ ┌─────────────────────────────┐
         │ │  SecureWipe(sessionKey)         │                               │ │  SecureWipe(sessionKey)     │
         │ │  Clear transfer context         │                               │ │  Clear transfer context     │
         │ │  Free encryption buffers        │                               │ │  Free encryption buffers    │
         │ │                                 │                               │ │                             │
         │ │  Perfect Forward Secrecy        │                               │ │  Perfect Forward Secrecy    │
         │ │    maintained                   │                               │ │    maintained               │
         │ └─────────────────────────────────┘                               │ └─────────────────────────────┘
```

---

## Attack Prevention

### Attack 1: Man-in-the-Middle (MITM) in Client-Server-Client Architecture

```
ATTACK ATTEMPT ON ALICE-SERVER CONNECTION:
Alice ────────────► Trudy ────────────► Server
     DH: g^a              DH: g^m

Trudy's Plan:
1. Intercept Alice's DH public key: g^a
2. Replace with her own DH key: g^m  
3. Sign g^m with her private key
4. Forward to server

PROTECTION MECHANISM:
┌─────────────────────────────────────────────────────────────────┐
│ Server Receives:                                                │
│ • DH Key: g^m (Trudy's key)                                     │
│ • Signature: Sign_Trudy(g^m)                                    │
│ • Claimed sender: "Alice"                                       │
│                                                                 │
│ Server Verification Process:                                    │
│ boolean valid = CryptoUtils.verifySignature(                    │
│     g^m,                    // Trudy's DH key                   │
│     Sign_Trudy(g^m),      // Trudy's signature                  │
│     Alice_Public_Key        // Alice's RSA public key           │
│ );                                                              │
│                                                                 │
│ Result: valid == FALSE                                          │
│ Reason: Trudy's signature doesn't match Alice's public key      │
└─────────────────────────────────────────────────────────────────┘

 ATTACK RESULT: FAILED!
Log: [SECURITY] Invalid signature on DH public key. Possible MITM attack.
Action: Connection rejected, IP logged for monitoring
```

### Attack 2: Replay Attack

```
 ATTACK ATTEMPT:
Time T1: Alice → Server: {encrypted_chunk, nonce: "xyz123:0:1640995200"}
Time T2:  Trudy replays same message 10 minutes later

 PROTECTION MECHANISM:
┌─────────────────────────────────────────────────────────────────┐
│ Server Anti-Replay Check (CryptoUtils.verifyIntegrity):         │
│                                                                 │
│ 1. Timestamp Validation:                                        │
│    currentTime = System.currentTimeMillis();                    │
│    messageAge = currentTime - message.timestamp;                │
│    if (messageAge > MAX_MESSAGE_AGE_MS) { // 5 minutes          │
│        return false; // Too old!                                │
│    }                                                            │
│                                                                 │
│ 2. Nonce Uniqueness Check:                                      │
│    String nonceKey = message.nonce + ":" + message.timestamp;   │
│    if (usedNonces.containsKey(nonceKey)) {                      │
│        return false; // Already used!                           │
│    }                                                            │
│                                                                 │
│ 3. Sequence Validation:                                         │
│    int sequenceNumber = parseSequence(message.nonce);           │
│    if (sequenceMap.containsKey(sequenceNumber)) {               │
│        return false; // Duplicate sequence!                     │
│    }                                                            │
└─────────────────────────────────────────────────────────────────┘

 ATTACK RESULT: FAILED!
Time Check: 10 minutes > 5 minutes MAX_AGE 
Nonce Check: "xyz123:0:1640995200" already in usedNonces 
Log: [SECURITY] Replay attack detected - duplicate nonce
Action: Message rejected, suspicious activity logged
```

### Attack 3: Data Tampering

```
 ATTACK ATTEMPT:
 Trudy intercepts chunk and modifies encrypted data:
Original: {encryptedData: "a7f9b2c8...", HMAC: "d3e1f4a7..."}
Modified: {encryptedData: "XXXXXXXX...", HMAC: "d3e1f4a7..."} ← Same HMAC!

 PROTECTION MECHANISM:
┌─────────────────────────────────────────────────────────────────┐
│ Server HMAC Verification (CryptoUtils.verifyIntegrity):         │
│                                                                 │
│ 1. Recalculate HMAC:                                            │
│    Mac hmac = Mac.getInstance("HmacSHA256");                    │
│    hmac.init(hmacKey);                                          │
│    hmac.update(message.encryptedData); // "XXXXXXXX..." ← Modified! │
│    hmac.update(message.iv);                                     │
│    hmac.update(message.timestamp.getBytes());                   │
│    hmac.update(message.nonce.getBytes());                       │
│    byte[] computedMAC = hmac.doFinal();                         │
│                                                                 │
│ 2. Compare MACs:                                                │
│    boolean valid = MessageDigest.isEqual(                       │
│        computedMAC,        // Calculated from modified data     │
│        message.mac         // Original HMAC                     │
│    );                                                           │
│    // Result: valid == FALSE                                    │
│    // Reason: HMAC of modified data ≠ original HMAC             │
└─────────────────────────────────────────────────────────────────┘

 ATTACK RESULT: FAILED!
HMAC Check: Computed HMAC ≠ Received HMAC 
Log: [SECURITY] MAC verification failed - possible tampering!
Action: Chunk rejected, transfer terminated for security violation
```

## Security Implementation Summary

secure file transfer protocol provides **enterprise-grade security** through:

### Cryptographic Protections

- **Perfect Forward Secrecy**: Ephemeral DH keys protect past communications
- **AES-256 Encryption**: Military-grade file content protection
- **RSA-2048 Signatures**: Strong authentication and non-repudiation
- **HMAC-SHA256**: Tamper-proof integrity verification

### Attack Prevention

- **MITM Prevention**: Digital signatures on all key exchanges
- **Replay Protection**: Unique nonces with timestamp validation
- **Data Tampering**: HMAC verification catches any modifications
- **DoS Protection**: Multi-tier rate limiting and IP blacklisting

### Real-Time Security

- **Continuous Monitoring**: Security events logged and analyzed
- **Automated Response**: Suspicious activity triggers protective measures
- **Memory Security**: Sensitive data wiped immediately after use
- **Threat Assessment**: Real-time security level evaluation
