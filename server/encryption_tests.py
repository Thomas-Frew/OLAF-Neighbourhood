import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def aes_gcm_encrypt(plaintext: bytes, key: bytes) -> bytes:
    # Generate a random 12-byte IV (standard for GCM)
    iv = os.urandom(12)

    # Create a Cipher object using AES algorithm in GCM mode
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the plaintext
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Get the authentication tag
    tag = encryptor.tag

    # Combine IV, ciphertext, and tag into a single byte string
    return iv + ciphertext + tag

def aes_gcm_decrypt(encrypted: bytes, key: bytes) -> bytes:
    # Extract the IV, ciphertext, and tag from the encrypted data
    iv = encrypted[:12]  # First 12 bytes are the IV
    tag = encrypted[-16:]  # Last 16 bytes are the authentication tag
    ciphertext = encrypted[12:-16]  # The remaining bytes are the ciphertext

    # Create a Cipher object for decryption
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext

def main():
    # Generate a random 16-byte key
    key = os.urandom(16)  # 128 bits key
    plaintext = b"This is a test message."  # Sample plaintext

    # Encrypt the plaintext
    encrypted = aes_gcm_encrypt(plaintext, key)

    # Print the encrypted data (IV + ciphertext + tag)
    print("Encrypted (hex):", encrypted.hex())

    # Decrypt the encrypted data
    decrypted = aes_gcm_decrypt(encrypted, key)

    # Print the decrypted plaintext
    print("Decrypted:", decrypted.decode())

if __name__ == "__main__":
    main()
