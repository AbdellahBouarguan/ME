from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

# Encrypt Function
def encrypt_file(password: str, input_file: str, output_file: str):
    # Generate a random salt
    salt = os.urandom(16)

    # Derive key from password using PBKDF2HMAC
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Generate a random 16-byte IV (initialization vector)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Read the input file data
    with open(input_file, 'rb') as f:
        data = f.read()

    # Pad data to be multiple of block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt the padded data
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Save salt, iv, and encrypted data into the output file
    with open(output_file, 'wb') as f:
        f.write(salt + iv + encrypted_data)

# Decrypt Function
def decrypt_file(password: str, input_file: str, output_file: str):
    # Read the input file (salt, iv, encrypted data)
    with open(input_file, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_data = f.read()

    # Derive the same key using the password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Decrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad the data
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    # Save decrypted data to the output file
    with open(output_file, 'wb') as f:
        f.write(data)

# Usage example

#encrypt_file(password, 'input.txt', 'encrypted.bin')
#decrypt_file(password, 'encrypted.bin', 'decrypted.txt')
