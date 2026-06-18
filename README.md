# hybrid-file-encryption

A Python CLI utility for encrypting and decrypting files using a **hybrid cryptographic scheme** — the same pattern used in TLS handshakes.

 

## How It Works

```
Plaintext file
      │
      ▼
[AES-128, EAX mode] ──── encrypted ciphertext + auth tag
      │
 session key (16 bytes, random)
      │
      ▼
[RSA-2048, PKCS1-OAEP] ── encrypted session key
      │
      ▼
  .enc file = [enc_session_key | nonce | tag | ciphertext]
```

1. A random 128-bit AES session key is generated per file.
2. The session key is encrypted with the recipient's RSA-2048 public key (PKCS1-OAEP padding).
3. The file is encrypted with AES in **EAX mode** — an authenticated encryption (AEAD) mode that provides both confidentiality and integrity.
4. The encrypted session key, AES nonce, authentication tag, and ciphertext are written to a single `.enc` file.

This mirrors the hybrid encryption approach used in the TLS handshake: asymmetric crypto for secure key transport, symmetric crypto for bulk data encryption.

## Requirements

- Python 3.8+
- [pycryptodome](https://pycryptodome.readthedocs.io/)

```bash
pip install -r requirements.txt
```

## Usage

### 1. Generate a key pair

```bash
python encryptor.py generate-keys
# Saves key_pair_private.pem and key_pair_public.pem to the current directory
```

> ⚠️ Keep `key_pair_private.pem` secret. Never commit it to version control.

### 2. Encrypt a file

```bash
python encryptor.py encrypt secret.txt
# Output: secret.txt.enc
```

### 3. Decrypt a file

```bash
python encryptor.py decrypt secret.txt.enc
# Output: secret.txt (restored)
```

Custom key paths are supported via `--public-key` / `--private-key` flags.  
See `examples/usage_example.md` for a full walkthrough with sample output.

## Cryptographic Choices

| Component | Algorithm | Rationale |
|-----------|-----------|-----------|
| Key transport | RSA-2048, PKCS1-OAEP | Secure asymmetric encryption with OAEP padding |
| Bulk encryption | AES-128, EAX mode | AEAD: provides both confidentiality and integrity |
| Key generation | `Crypto.Random.get_random_bytes` | Cryptographically secure random source |

## Security Notes

- Private keys are generated locally and **never stored in this repository**.
- AES-EAX authentication tag prevents undetected tampering with the ciphertext.
- RSA key size is 2048 bits — sufficient for current security requirements.
- Session keys are single-use (generated fresh per file encryption).

## Project Structure

```
hybrid-file-encryption/
├── encryptor.py       # CLI entry point + encryption logic
├── requirements.txt   # Python dependencies
├── .gitignore         # Excludes *.pem and *.enc from version control
├── README.md
└── examples/
    └── usage_example.md   # Full walkthrough with sample output
```

## License

This project is licensed under the MIT License – see the LICENSE file for details.
