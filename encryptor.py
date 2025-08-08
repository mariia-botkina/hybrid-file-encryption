from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

def generate_keys(filename="key_pair"):
    # Генерируем 2048-битный RSA-ключ
    key = RSA.generate(2048)

    # Сохраняем приватный ключ в файл
    private_key_file = open(f"{filename}_private.pem", "wb")
    private_key_file.write(key.export_key())
    private_key_file.close()

    # Сохраняем публичный ключ в файл
    public_key_file = open(f"{filename}_public.pem", "wb")
    public_key_file.write(key.publickey().export_key())
    public_key_file.close()

    print(f"Ключи сохранены в файлы: {filename}_private.pem и {filename}_public.pem")


def encrypt_file(filename, public_key_file="key_pair_public.pem"):
    # Считываем публичный ключ
    with open(public_key_file, "rb") as key_file:
        public_key = RSA.import_key(key_file.read())

    # Генерируем случайный симметричный ключ (AES)
    session_key = get_random_bytes(16)

    # Шифруем сессионный ключ с помощью публичного ключа RSA
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Шифруем сам файл с помощью симметричного ключа
    with open(filename, "rb") as file_in:
        with open(f"{filename}.enc", "wb") as file_out:
            file_out.write(enc_session_key) # Записываем зашифрованный ключ
            
            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(file_in.read())
            file_out.write(cipher_aes.nonce)
            file_out.write(tag)
            file_out.write(ciphertext)

    print(f"Файл {filename} зашифрован. Зашифрованный файл: {filename}.enc")


def decrypt_file(filename, private_key_file="key_pair_private.pem"):
    # Считываем приватный ключ
    with open(private_key_file, "rb") as key_file:
        private_key = RSA.import_key(key_file.read())
        
    # Считываем данные из зашифрованного файла
    with open(filename, "rb") as file_in:
        enc_session_key, nonce, tag, ciphertext = \
            [file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]

    # Расшифровываем сессионный ключ с помощью приватного ключа RSA
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Расшифровываем сам файл с помощью симметричного ключа
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    
    # Сохраняем расшифрованные данные
    with open(filename.replace(".enc", ""), "wb") as file_out:
        file_out.write(data)

    print(f"Файл {filename} расшифрован.")


if __name__ == "__main__":
    generate_keys()
    
    # Создадим тестовый файл
    test_message = b"This is a secret message for our project!"
    with open("test_file.txt", "wb") as f:
        f.write(test_message)
    print("\nСоздан тестовый файл 'test_file.txt'.\n")

    # Зашифруем файл
    encrypt_file("test_file.txt")
    
    # Расшифруем файл
    # Удалим исходный файл, чтобы убедиться, что расшифровка работает
    import os
    os.remove("test_file.txt")
    decrypt_file("test_file.txt.enc")
