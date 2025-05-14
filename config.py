import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend

BLOCK_SIZE = 16  # AES block size (in bytes)

def get_private_key(password: str) -> bytes:
    """Generate a 32-byte AES key from the password using PBKDF2."""
    salt = b"this_is_a_salt"  # Use a securely generated unique salt in production
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())  # Convert password to bytes

def encrypt(data: str, password: str) -> str:
    """Encrypt data using AES-256-CBC."""
    key = get_private_key(password)
    iv = os.urandom(BLOCK_SIZE)

    # Pad the plaintext to block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Return base64 encoded string (IV + ciphertext)
    return base64.b64encode(iv + encrypted_data).decode('utf-8')

def decrypt(encrypted_data: str, password: str) -> str:
    """Decrypt data using AES-256-CBC."""
    encrypted_data_bytes = base64.b64decode(encrypted_data)
    iv = encrypted_data_bytes[:BLOCK_SIZE]
    ciphertext = encrypted_data_bytes[BLOCK_SIZE:]

    key = get_private_key(password)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data.decode('utf-8')

# Example usage
#if __name__ == "__main__":
password = "my_secure_password"
api_key = "AIzaSyCXV9AYcGLu5GaoTZ6j5WvzqeGeZ5bDPds"
user_password = "Admin@312023"
user_name = "Admin@ltts.com"

encrypted_api_key = encrypt(api_key, password)
encrypted_user_password = encrypt(user_password, user_name)

#    print(f"Encrypted API Key: {encrypted_api_key}")
#    decrypted_api_key = decrypt(encrypted_api_key, password)
#    print(f"Decrypted API Key: {decrypted_api_key}")
