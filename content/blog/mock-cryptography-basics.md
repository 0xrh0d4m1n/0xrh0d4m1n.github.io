---
title: "Cryptography Fundamentals for Security Practitioners"
date: 2024-04-20
description: "A practical introduction to cryptographic concepts including symmetric/asymmetric encryption, hashing, digital signatures, and PKI."
tags: ["cryptography", "blue-team", "networking", "python", "fundamentals"]
categories: ["Security"]
image: "https://picsum.photos/seed/crypto19/800/400"
authors:
  - name: "0xrh0d4m1n"
    link: "https://github.com/0xrh0d4m1n"
    image: "https://github.com/0xrh0d4m1n.png"
---

## Why Cryptography Matters

Cryptography is the foundation of **information security**. It provides confidentiality, integrity, authentication, and non-repudiation for data in transit and at rest.

## Symmetric vs Asymmetric Encryption

### Key Differences

| Property | Symmetric | Asymmetric |
|----------|-----------|------------|
| Keys | Single shared key | Public + Private key pair |
| Speed | **Fast** | Slow |
| Key Distribution | Challenging | Easy (public key) |
| Use Case | Bulk data encryption | Key exchange, signatures |
| Examples | AES, ChaCha20 | RSA, ECC, Ed25519 |

### Symmetric Encryption with Python

```python
from cryptography.fernet import Fernet

# Generate a key
key = Fernet.generate_key()
cipher = Fernet(key)

# Encrypt
plaintext = b"Sensitive data to protect"
ciphertext = cipher.encrypt(plaintext)
print(f"Encrypted: {ciphertext}")

# Decrypt
decrypted = cipher.decrypt(ciphertext)
print(f"Decrypted: {decrypted.decode()}")
```

### AES Encryption (More Control)

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

key = os.urandom(32)  # AES-256
iv = os.urandom(16)

# Encrypt
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()
padder = padding.PKCS7(128).padder()

data = b"Secret message!"
padded_data = padder.update(data) + padder.finalize()
ciphertext = encryptor.update(padded_data) + encryptor.finalize()
```

## Hashing

Hash functions produce a **fixed-size output** from arbitrary input. They are *one-way* functions -- you cannot reverse a hash to get the original data.

### Common Hash Algorithms

1. **MD5** -- 128-bit, deprecated, vulnerable to collisions
2. **SHA-1** -- 160-bit, deprecated for signatures
3. **SHA-256** -- 256-bit, widely used and secure
4. **SHA-3** -- latest standard, Keccak-based
5. **BLAKE2** -- fast and secure, good for checksums

```bash
# Generate hashes from the command line
echo -n "password123" | md5sum
echo -n "password123" | sha256sum
echo -n "password123" | sha512sum

# Hash a file
sha256sum suspicious_file.exe

# Compare file integrity
sha256sum --check checksums.txt
```

### Password Hashing

> Never use plain hash functions for passwords. Always use a **dedicated password hashing algorithm** with salt and work factor.

```python
import bcrypt

# Hash a password
password = b"MySecurePassword123!"
salt = bcrypt.gensalt(rounds=12)
hashed = bcrypt.hashpw(password, salt)

# Verify
if bcrypt.checkpw(password, hashed):
    print("Password matches!")
```

## Digital Signatures

Digital signatures provide **authentication** and **non-repudiation**:

```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

# Generate key pair
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# Sign a message
message = b"This message is authentic"
signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))

# Verify the signature
try:
    public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    print("Signature is valid!")
except Exception:
    print("Signature verification failed!")
```

## TLS in Practice

```bash
# Inspect a server's TLS certificate
openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null | \
  openssl x509 -noout -subject -issuer -dates

# Generate a self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

Understanding these fundamentals is essential for every security professional. Cryptography underpins everything from **HTTPS** to *VPNs*, *disk encryption*, and *secure messaging*.
