import argparse
import os
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP


def generate_keys(output_dir=".", filename="key_pair"):
    """Generate RSA-2048 key pair and save to PEM files."""
    key = RSA.generate(2048)

    private_path = os.path.join(output_dir, f"{filename}_private.pem")
    public_path = os.path.join(output_dir, f"{filename}_public.pem")

    with open(private_path, "wb") as f:
        f.write(key.export_key())

    with open(public_path, "wb") as f:
        f.write(key.publickey().export_key())

    print(f"[+] Key pair saved to: {private_path}, {public_path}")


def encrypt_file(filename, public_key_file="key_pair_public.pem"):
    """
    Encrypt a file using hybrid encryption (RSA + AES-EAX).

    File format (.enc):
        [256 bytes] RSA-encrypted AES session key
        [16 bytes]  AES nonce
        [16 bytes]  AES authentication tag
        [N bytes]   AES-EAX ciphertext
    """
    with open(public_key_file, "rb") as f:
        public_key = RSA.import_key(f.read())

    session_key = get_random_bytes(16)

    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    with open(filename, "rb") as f:
        ciphertext, tag = cipher_aes.encrypt_and_digest(f.read())

    out_path = f"{filename}.enc"
    with open(out_path, "wb") as f:
        f.write(enc_session_key)
        f.write(cipher_aes.nonce)
        f.write(tag)
        f.write(ciphertext)

    print(f"[+] Encrypted: {filename} -> {out_path}")


def decrypt_file(filename, private_key_file="key_pair_private.pem"):
    """
    Decrypt a file encrypted with encrypt_file().
    Verifies AES-EAX authentication tag before writing output.
    """
    with open(private_key_file, "rb") as f:
        private_key = RSA.import_key(f.read())

    key_size = private_key.size_in_bytes()
    with open(filename, "rb") as f:
        enc_session_key = f.read(key_size)
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    out_path = filename.replace(".enc", "")
    with open(out_path, "wb") as f:
        f.write(data)

    print(f"[+] Decrypted: {filename} -> {out_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Hybrid file encryption utility (RSA + AES-EAX)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # generate-keys
    gen = subparsers.add_parser("generate-keys", help="Generate RSA key pair")
    gen.add_argument("--output-dir", default=".", help="Directory to save keys (default: .)")
    gen.add_argument("--name", default="key_pair", help="Key file prefix (default: key_pair)")

    # encrypt
    enc = subparsers.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("file", help="Path to the file to encrypt")
    enc.add_argument("--public-key", default="key_pair_public.pem", help="Path to RSA public key")

    # decrypt
    dec = subparsers.add_parser("decrypt", help="Decrypt a .enc file")
    dec.add_argument("file", help="Path to the .enc file to decrypt")
    dec.add_argument("--private-key", default="key_pair_private.pem", help="Path to RSA private key")

    args = parser.parse_args()

    if args.command == "generate-keys":
        generate_keys(output_dir=args.output_dir, filename=args.name)
    elif args.command == "encrypt":
        encrypt_file(args.file, public_key_file=args.public_key)
    elif args.command == "decrypt":
        decrypt_file(args.file, private_key_file=args.private_key)


if __name__ == "__main__":
    main()
