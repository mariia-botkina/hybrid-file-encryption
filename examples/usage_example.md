# Usage Example

A complete walkthrough of `encryptor.py` — from key generation to decryption.

## Environment

```
Python 3.11.4
pycryptodome 3.20.0
```

## Step 1 — Generate a key pair

```bash
$ python encryptor.py generate-keys
[+] Key pair saved to: ./key_pair_private.pem, ./key_pair_public.pem
```

Two PEM files are created locally. The private key must be kept secret and is excluded from version control via `.gitignore`.

```
key_pair_private.pem   ← keep this secret, never commit
key_pair_public.pem    ← can be shared freely
```

You can also specify a custom output directory and key name prefix:

```bash
$ python encryptor.py generate-keys --output-dir ./keys --name alice
[+] Key pair saved to: ./keys/alice_private.pem, ./keys/alice_public.pem
```

## Step 2 — Prepare a file to encrypt

```bash
$ echo "This is a secret message." > secret.txt
$ cat secret.txt
This is a secret message.
```

## Step 3 — Encrypt the file

```bash
$ python encryptor.py encrypt secret.txt
[+] Encrypted: secret.txt -> secret.txt.enc
```

The output `.enc` file has the following binary layout:

```
Offset        Size        Content
──────────────────────────────────────────────────────────
0             256 bytes   RSA-encrypted AES session key
256           16 bytes    AES nonce
272           16 bytes    AES-EAX authentication tag
288           N bytes     AES-EAX ciphertext
```

## Step 4 — Verify confidentiality

Delete the original file to confirm decryption works from the `.enc` alone:

```bash
$ rm secret.txt
$ ls
encryptor.py  key_pair_private.pem  key_pair_public.pem
requirements.txt  secret.txt.enc
```

## Step 5 — Decrypt the file

```bash
$ python encryptor.py decrypt secret.txt.enc
[+] Decrypted: secret.txt.enc -> secret.txt

$ cat secret.txt
This is a secret message.
```

The authentication tag is verified automatically during decryption. If the ciphertext has been tampered with, `pycryptodome` raises `ValueError: MAC check failed` before any plaintext is written.

## Step 6 — Custom key paths

If your keys are stored in a separate directory or have a non-default name:

```bash
$ python encryptor.py encrypt report.pdf --public-key ./keys/alice_public.pem
[+] Encrypted: report.pdf -> report.pdf.enc

$ python encryptor.py decrypt report.pdf.enc --private-key ./keys/alice_private.pem
[+] Decrypted: report.pdf.enc -> report.pdf
```

## Error cases

| Situation | Error |
|-----------|-------|
| Wrong private key used for decryption | `ValueError: Incorrect decryption` (OAEP) |
| Ciphertext tampered with | `ValueError: MAC check failed` (EAX tag) |
| Key file not found | `FileNotFoundError` |
| Encrypted file corrupted / truncated | `ValueError` or `struct` read error |

## Full help reference

```bash
$ python encryptor.py --help
usage: encryptor.py [-h] {generate-keys,encrypt,decrypt} ...

Hybrid file encryption utility (RSA + AES-EAX)

positional arguments:
  {generate-keys,encrypt,decrypt}
    generate-keys       Generate RSA key pair
    encrypt             Encrypt a file
    decrypt             Decrypt a .enc file

$ python encryptor.py encrypt --help
usage: encryptor.py encrypt [-h] [--public-key PUBLIC_KEY] file

positional arguments:
  file                  Path to the file to encrypt

options:
  --public-key          Path to RSA public key (default: key_pair_public.pem)

$ python encryptor.py decrypt --help
usage: encryptor.py decrypt [-h] [--private-key PRIVATE_KEY] file

positional arguments:
  file                  Path to the .enc file to decrypt

options:
  --private-key         Path to RSA private key (default: key_pair_private.pem)
```
