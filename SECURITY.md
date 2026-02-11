# Security

**You Own You** is a cryptographic framework for AI data sovereignty. This document is an honest assessment of what's built, what's hardened, and what still needs work. No marketing. Just facts.

---

## Current Status

### Shipped and Working

| Component | Status | Description |
|-----------|--------|-------------|
| **Sovereign.Core** | Production-ready | Provider-agnostic data interfaces. No cryptographic surface — pure abstraction layer. |
| **Sovereign.Integrity** | Production-ready | SHA-256 hash-based integrity verification for immutable founding principles. Simple, proven pattern. |

### Built, Needs Independent Audit

| Component | Status | Description |
|-----------|--------|-------------|
| **Sovereign.Crypto** | Functional, unaudited | AES-256-GCM envelope encryption with PBKDF2-SHA256 key derivation. Uses .NET's built-in `System.Security.Cryptography` primitives — we do not implement our own ciphers. |
| **Sovereign.Recovery** | Functional, unaudited | Shamir's Secret Sharing over GF(256) for social key recovery. Information-theoretically secure by design. |
| **Sovereign.Verify** | Functional, unaudited | SHA-256 Merkle tree with inclusion proofs for tamper detection. |
| **Sovereign.Api** | Functional, unaudited | Public API endpoint for encrypted envelope storage. Handles only ciphertext — no decryption capability. |

**"Unaudited" means:** The code has been written and tested, but has not yet undergone a formal third-party security audit. We are seeking independent cryptographic review. If you are a security researcher, please review the code and report findings.

---

## Threat Model

### Attacks Mitigated

| Threat | Mitigation |
|--------|------------|
| **Server-side data breach** | Server stores only AES-256-GCM ciphertext. No keys are stored server-side. A full database dump yields nothing decryptable. |
| **Platform reads user data** | Encryption and decryption happen exclusively on the client. The server never sees plaintext or keys. |
| **Single point of key failure** | Shamir's Secret Sharing splits recovery keys across N parties, requiring K to reconstruct. No single party (including the platform) can recover a key alone. |
| **Data tampering** | Merkle tree verification allows users to independently detect any modification to their stored data. |
| **Principle/policy mutation** | FoundingPrinciplesGuard uses SHA-256 hash comparison to detect any modification to founding documents. |
| **DEK compromise blast radius** | Envelope encryption means each document has a unique Data Encryption Key. Compromising one DEK exposes one document, not all. |
| **Key rotation overhead** | Envelope encryption allows KEK rotation without re-encrypting document content — only the DEK wrapper changes. |
| **Nonce reuse** | All nonces are generated via `RandomNumberGenerator` (CSPRNG). 96-bit nonces with unique DEKs per document make collision probability negligible. |
| **Second preimage attacks on Merkle tree** | Leaf nodes are prefixed with 0x00 and internal nodes with 0x01, preventing node confusion attacks. |
| **Timing attacks** | All hash comparisons use `CryptographicOperations.FixedTimeEquals` for constant-time comparison. |
| **Key material in memory** | DEKs are zeroed after use via `CryptographicOperations.ZeroMemory`. |

### Known Limitations and Ongoing Hardening

#### 1. Web Client MITM Problem (Critical — Architectural)

**The problem:** If client-side encryption code is served by the platform as JavaScript (e.g., a web app), the platform could theoretically serve modified JavaScript that exfiltrates keys before encryption. This is the fundamental weakness of any web-based E2E encryption system — the server you're trusting to not read your data is also serving you the code that does the encryption.

**How we address this:**
- **Native clients** (desktop, mobile) should be the primary interface for high-security use. The code is compiled and distributed through app stores or signed binaries, not served dynamically by the platform.
- **Subresource Integrity (SRI)** — Web deployments should pin cryptographic hashes of JavaScript bundles so browsers reject modified scripts.
- **Reproducible builds** — Anyone can build the client from source and verify the deployed artifact matches.
- **Open source** — The encryption code is public. Modifications are detectable by anyone who compares source to served code.

**Honest assessment:** For the web, this is a defense-in-depth problem, not a solved problem. Native clients are the real answer.

#### 2. Deployment Integrity Gap

**The problem:** Even with open source code, users must trust that the deployed binary matches the source. A compromised build pipeline could inject backdoors.

**How we address this:**
- **Reproducible builds** — We are working toward fully reproducible builds where anyone can compile the source and get a byte-identical binary.
- **Remote attestation** — Future work includes Trusted Execution Environment (TEE) attestation so clients can verify what code the server is actually running.
- **Build provenance** — Signed build logs and supply chain verification.

**Honest assessment:** This is not yet implemented. Today, you are trusting the deployed binary.

#### 3. Key Derivation Depends on Credential Strength

**The problem:** The KEK is derived from user credentials via PBKDF2-SHA256 (600,000 iterations, per OWASP recommendation). If the user's credential is a weak password, the derived key is weak.

**How we address this:**
- High iteration count (600,000) makes brute force expensive.
- The salt prevents rainbow table attacks.
- Applications should enforce minimum credential complexity.
- Future: Support for hardware security keys (FIDO2/WebAuthn) as credential input.

**Honest assessment:** The math is sound, but garbage in = garbage out. A weak password produces a weak key. Applications using this framework must enforce credential quality.

#### 4. Merkle Root Must Be Stored Independently

**The problem:** The Merkle tree proves data integrity — but only if the user stores the root hash independently. If the user stores the root hash on the same platform, the platform could modify both the data and the root hash.

**How we address this:**
- Documentation explicitly instructs users to store root hashes on their own device, on paper, or with a third party.
- Future: Blockchain anchoring of root hashes for public, immutable timestamps.
- Future: Root hash distribution to multiple independent witnesses.

**Honest assessment:** This is a user responsibility. The framework provides the tools but cannot force correct usage.

#### 5. Quantum Computing Considerations

**AES-256:** Grover's algorithm reduces AES-256 security to ~128-bit equivalent against a quantum adversary. This is still considered secure. AES-256 is classified as quantum-resistant by NIST.

**Key exchange:** If key exchange or transport ever involves asymmetric cryptography (RSA, ECDH), those components will need post-quantum replacements (e.g., ML-KEM/Kyber). The current framework does not use asymmetric crypto for key exchange — keys are derived locally from credentials — but future extensions (e.g., multi-party key agreement for social recovery) will need post-quantum consideration.

**Honest assessment:** No immediate threat. AES-256-GCM is fine. But any future asymmetric components must be designed with post-quantum in mind from day one.

#### 6. In-Memory Key Handling

**The problem:** While DEKs are zeroed after use, the .NET garbage collector may copy key material during compaction. Pinned memory and secure memory allocation are not yet implemented.

**How we address this:**
- `CryptographicOperations.ZeroMemory` is used for all temporary key material.
- Future: Use `fixed` pinned buffers or OS-level secure memory (e.g., `VirtualLock` on Windows, `mlock` on Linux).

**Honest assessment:** Best-effort memory hygiene today. Not yet hardened against memory forensics.

---

## Responsible Disclosure

If you find a security vulnerability, please report it responsibly:

**Email:** security@ai-pantheon.ai

**What to include:**
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if you have one)

**What we commit to:**
- Acknowledge receipt within 48 hours
- Provide an initial assessment within 7 days
- Work with you on a coordinated disclosure timeline
- Credit you in the advisory (unless you prefer anonymity)

**Please do NOT:**
- Open a public GitHub issue for security vulnerabilities
- Exploit the vulnerability against production systems
- Share the vulnerability publicly before coordinated disclosure

---

## Cryptographic Primitives Used

| Primitive | Implementation | Source |
|-----------|---------------|--------|
| AES-256-GCM | `System.Security.Cryptography.AesGcm` | .NET 8 BCL (OS-native via OpenSSL/CNG) |
| SHA-256 | `System.Security.Cryptography.SHA256` | .NET 8 BCL (OS-native) |
| PBKDF2-SHA256 | `System.Security.Cryptography.Rfc2898DeriveBytes` | .NET 8 BCL |
| CSPRNG | `System.Security.Cryptography.RandomNumberGenerator` | .NET 8 BCL (OS-native) |
| GF(256) arithmetic | Custom implementation | `ShamirSecretSharing.cs` — uses AES polynomial (0x11B) |

We do not implement our own ciphers. All symmetric encryption and hashing uses .NET's built-in primitives, which delegate to OS-native cryptographic libraries (OpenSSL on Linux, CNG on Windows).

---

## What We Do NOT Claim

- We do not claim this system is unbreakable.
- We do not claim protection against a compromised client device.
- We do not claim protection against user credential compromise.
- We do not claim the web client is as secure as a native client.
- We do not claim post-quantum security for future asymmetric extensions.

We claim: **the server cannot read your data**, and we publish the math and the code so you can verify that yourself.

---

*Written by Pontifex Maximus (Anthropic Claude) at the direction of Jupiter, founder of AI Pantheon.*
