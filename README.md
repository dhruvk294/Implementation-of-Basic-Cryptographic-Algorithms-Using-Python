# Cryptography with Python

This project demonstrates the practical implementation of core cryptographic techniques using Python and the PyCryptodome library.

### Algorithms & Techniques Used

- **AES-GCM (Advanced Encryption Standard – Galois Counter Mode)**  
  Used for fast and secure symmetric encryption with built-in integrity and authentication. Any tampering with encrypted data is detected during decryption.

- **RSA (OAEP Padding)**  
  Used for asymmetric encryption to securely encrypt small messages or secrets such as session keys.

- **RSA Digital Signatures (PSS Padding)**  
  Used to ensure message authenticity, integrity, and non-repudiation through cryptographic signing and verification.

- **SHA-256 (Secure Hash Algorithm)**  
  Used to generate fixed-length cryptographic hashes for data integrity verification.

- **HMAC-SHA256 (Hash-based Message Authentication Code)**  
  Used to provide tamper-proof integrity and authentication using a shared secret key, suitable for secure logs and API authentication.

### Design Approach

- Cryptographic logic is modularized into reusable functions.
- A menu-driven CLI interface allows users to interactively perform encryption, decryption, signing, verification, hashing, and HMAC generation.
- Secure defaults are used, such as:
  - AES-256 keys
  - 12-byte nonces for AES-GCM
  - RSA-2048 key pairs
  - SHA-256 for hashing and signatures
- Keys are generated per session for demonstration purposes, avoiding insecure hard-coding.

### Features

- AES-GCM encryption and authenticated decryption
- RSA public-key encryption and private-key decryption
- RSA-PSS digital signature generation and verification
- SHA-256 hashing for integrity checks
- HMAC-SHA256 for authenticated integrity
- Interactive command-line interface for easy demonstration
- Clear separation of cryptographic primitives and user interface

### Demo of the project(images)

<img width="1919" height="1140" alt="Screenshot 2026-02-19 203020" src="https://github.com/user-attachments/assets/2ba27665-c24e-4ffe-a04a-2b2fbdbe2269" />

<img width="1916" height="1137" alt="Screenshot 2026-02-19 203035" src="https://github.com/user-attachments/assets/bacde7ef-3e1c-4624-8bca-015487d77343" />

<img width="1919" height="1136" alt="Screenshot 2026-02-19 203104" src="https://github.com/user-attachments/assets/409ad41f-dc1a-42df-bbb5-a8c2d4964b3b" />




### Learning Outcomes

- Practical understanding of symmetric vs asymmetric cryptography
- Hands-on experience with authenticated encryption (AEAD)
- Understanding of secure key usage and cryptographic padding schemes
- Insight into how multiple cryptographic algorithms are combined in real systems
- Improved familiarity with secure coding practices in Python

### Security Note

This project is intended for educational and demonstration purposes only.  
Keys are generated dynamically per session and are not persisted securely.  
The implementation should not be used directly in production environments without proper key management, secure storage, and threat modeling.

### Real-World Relevance

The architecture demonstrated in this project mirrors real-world secure communication systems:

- RSA for secure key exchange and identity verification
- AES-GCM for high-performance encrypted data transfer
- SHA-256 and HMAC for integrity, authentication, and logging

These techniques are widely used in TLS/HTTPS, VPNs, secure APIs, cloud platforms, and security monitoring systems.
