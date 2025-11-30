# End-to-End Encrypted Web-Chat (PoC)

A browser-based simulation demonstrating how secure messaging 
applications function with React. This project implements uses hybrid encryption entirely in the 
client-side browser using Next.js, React, and the native [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)

---

[![Source Code](https://img.shields.io/badge/source-github-blue)](https://github.com/lpj-app/encrypted-webchat-poc)
[![License: Apache 20](https://img.shields.io/badge/license-Apache%20License%202.0-blue)](https://img.shields.io/badge/license-Apache%20License%202.0-blue)

[![Made with Next.js](https://img.shields.io/badge/Made%20with-Next.js-black?logo=next.js)](https://nextjs.org/) [![React](https://img.shields.io/badge/React-blue?logo=react)](https://reactjs.org/) [![TypeScript](https://img.shields.io/badge/TypeScript-blue?logo=typescript)](https://www.typescriptlang.org/)

---
# Contents
[1. Core Concept: Hybrid Encryption](#1-core-concept-hybrid-encryption) 

[2. Implementation](#2-implementation)
- [2.1 Cryptographic Primitives](#21-cryptographic-primitives)
- [2.2 Memory Management & Key Storage](#22-memory-management--key-storage)
- [2.3 The Handshake Protocol (Code Walkthrough)](#23-the-handshake-protocol-code-walkthrough)
  - [2.3.1 Procedure](#231-procedure)
  - [2.3.2 Code Walkthrough](#232-code-walkthrough)
- [2.4 Message Transport (AES-GCM)](#24-message-transport-aes-gcm)

[3. How to Run](#3-how-to-run)

[4. What the server sees](#4-what-the-server-sees)

[5. PoC Limits](#5-poc-limits)

[6. Key words](#6-key-words)

---
## 1. Core Concept: Hybrid Encryption

In cryptography, there are two main types of encryption, each with a trade-off:

* **Asymmetric (RSA):** Public Key (to lock) and a Private Key (to unlock), great for sharing secrets safely, but mathematically complex and slow for large data.
* **Symmetric (AES):** Uses a single key to lock and unlock. Much faster, but suffers from the "Key Distribution Problem"—how to get the key to the other chat partner without a hacker seeing it?

**Solution:** Combining them; the slow, secure RSA keys *only* to exchange a fast, temporary AES key. This is **Hybrid Encryption**.

-----

## 2. Implementation

Real cryptographic implementation running in the browser's memory. Here is how `window.crypto` API is orchestrated.

### 2.1 Cryptographic Primitives

We rely on the browser's native `SubtleCrypto` engine. No external crypto libraries (like `tweetnacl` or `crypto-js`) are used.

| Component | Standard | Spec | Rationale |
| :--- | :--- | :--- | :--- |
| **Identity** | RSA-OAEP | 2048-bit, SHA-256 | High compatibility. We use OAEP padding to prevent chosen-ciphertext attacks. |
| **Transport** | AES-GCM | 256-bit | Authenticated Encryption. GCM provides confidentiality *and* integrity (it detects tampering). |
| **Key Wrap** | RSA-OAEP | -- | Used specifically to envelop the AES session key during the handshake. |
| **Entropy** | CSPRNG | `getRandomValues()` | Cryptographically secure randomness for IVs and Key generation. |

### 2.2 Memory Management & Key Storage

**Critical:** Keys are **never** written to `localStorage`, `cookies`, or `IndexedDB`.

* **Private Keys:** Stored in a React `useState` hook as non-exportable `CryptoKey` objects. If you refresh the page, the identity is destroyed. This simulates "ephemeral" sessions.
* **Public Keys:** Exported to **SPKI** (Subject Public Key Info) format, Base64 encoded, and stored in the "Server" directory state so other clients can find them.

### 2.3 The Handshake Protocol (Code Walkthrough)

#### 2.3.1 Procedure

##### Phase A: Identity Generation (On Load)

When the application starts, both "Alice" and "Bob" act as separate clients running in your browser <br/> 
**Key gen**: Each user generates a permanent RSA Key Pair. <br/>
**Publishing**: They upload their Public Key to the "Server" (the directory). <br/>
**Storage**: They keep their Private Key strictly in memory (never sent over the network). <br/>
<br/>
##### Phase B: The Handshake - First Message

Alice wants to send "Hello" to Bob. She doesn't have a secure channel yet. <br/>
**Session Key**: Alice generates a random 256-bit AES key. <br/>
**Wrapping**: Alice takes Bob's Public RSA Key and uses it to encrypt this new AES key. This creates an encrypted "bundle." <br/>
**Encryption**: Alice uses the AES key to encrypt the text "Hello." <br/>
**Transport**: Alice sends a packet containing:
- The Encrypted Message (AES)
- The Encrypted Key Bundle (RSA)
- The AES IV (Metadata)

##### Phase C: Decryption - Receiving
Bob receives the packet. <br>
**Unwrapping**: Bob sees the encrypted key bundle. He uses his Private RSA Key to decrypt it, revealing the AES Session Key. <br>
**Decryption**: Now holding the AES key, he uses it to decrypt the message text. <br>
**Persistence**: Bob stores the AES key in memory. <br>

##### Phase D: Subsequent Messages
For the next message, Alice and Bob already have the shared AES key. 
They skip the heavy RSA operations and just send AES-encrypted messages. 
This makes the chat extremely fast.


#### 2.3.2 Code Walkthrough
The code does not use a Diffie-Hellman Key Exchange. Instead, it uses a **Key Encapsulation Mechanism (KEM)** approach triggered by the first message.

**Step 1: Identity Generation**
Function: `generateKeyPair()`
On load, the browser calls `crypto.subtle.generateKey` with `["encrypt", "decrypt"]` usage. The private key remains explicitly non-extractable in a real-world scenario (though enabled here for debug visualization).

**Step 2: Session Initialization (Lazy Loading)**
When Alice types the first message, the app detects she has no `sessionKey` for Bob.

1.  **Generation:** `generateSessionKey()` creates a raw 256-bit AES-GCM key.
2.  **Encapsulation:** `encryptSessionKey()` takes this raw AES key and encrypts it using **Bob's Public RSA Key**.
    * *Result:* A binary blob that *only* Bob's Private Key can open.

**Step 3: The Packet Structure**
The application constructs a strictly typed `MessagePacket` object. This is what actually crosses the "wire":

```typescript
type MessagePacket = {
    id: string;
    sender: string;
    // The actual payload. Random bytes to the naked eye.
    encryptedContent: ArrayBuffer; 
    // CRITICAL: A unique 12-byte buffer for AES-GCM
    iv: Uint8Array; 
    // Attached ONLY on the first message (The Handshake)
    encryptedSessionKey?: ArrayBuffer; 
};
```

### 2.4 Message Transport (AES-GCM)

Every specific message triggers `encryptMessage()`:

1.  **IV Generation:** We generate a fresh 12-byte Initialization Vector (`iv`) using `crypto.getRandomValues`. Reusing an IV with the same key in AES-GCM is a catastrophic failure mode, so we ensure uniqueness per message.
2.  **Encryption:** `crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data)` is called.
3.  **Output:** The function returns the Ciphertext.

**Note on The Server:**
The "Server Log" component in the UI receives the full `MessagePacket`. However, because it lacks the Private RSA keys, the `encryptedSessionKey` is useless to it. Because it lacks the Session Key, the `encryptedContent` is noise. It can only see metadata: `sender`, `timestamp`, and `iv`.

-----

## 3. How to Run
Test the live demo here and checkout the extended debug / logging mode <br/>
[![Test it live here](https://img.shields.io/badge/demo-online-brightgreen)](https://lpj.app/encrypted-webchat-poc)

**OR**

1.  Clone the repository.
2.  Install dependencies:
    ```bash
    npm install
    # or
    yarn install
    ```
3.  Run the development server:
    ```bash
    npm run dev
    ```
4.  Open `http://localhost:3000`

## 4. What the server sees

The middle pane in the application represents the server log. <br/> 
Even with "Debug Mode" enabled, the server is blind to the content.

**Visible to Server:**
- Sender/Receiver IDs: Who is talking to whom. 
- Timestamps: When the message was sent.
- Payload Size: Rough estimate of message length.
- IV (Initialization Vector): Required for decryption, but useless without the key.
- Public Keys: Necessary for the directory service.

**Hidden from Server:**
- Message Content: It only sees randomized bytes (Ciphertext).
- Private Keys: These never leave the client device.
- Session Keys: These travel across the wire encrypted.

## 5. PoC Limits

- **No Signature/Auth:** While we use RSA for encryption, we are not signing messages (RSA-PSS or ECDSA). This prevents passive sniffing but does not technically prevent an active Man-in-the-Middle from replacing Public Keys (TOFU - Trust On First Use model is assumed here).
- **Persistence:** As noted, keys die on page refresh. A real app would store the *Encrypted* Private Key in `IndexedDB` and ask for a password to decrypt it on load.


## 6. Key words

**Public Key**: An identity card. You give this to everyone so they can send you secrets.

**Private Key**: The master key. Keeps your secrets safe. If you lose this, you can't read your messages. Never share this.

**Session Key**: A temporary key used for a specific conversation. It's often rotated (changed) periodically for security.

**IV (Initialization Vector)**: A random number used to ensure that if you encrypt the word "Hello" twice, the output looks different both times. It prevents pattern analysis.

**Ciphertext**: The unreadable, encrypted result.

---
## License

See [LICENSE](./LICENSE).

--- 

&copy; [lpj.app](https://github.com/lpj-app). Licensed under Apache 2.0. UI redesigned by [Gemini](https://gemini.google.com)
