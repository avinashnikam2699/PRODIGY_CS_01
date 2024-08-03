from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def generate_key():
    """Generate a random 32-byte key."""
    return os.urandom(32)

def encrypt(message, key):
    """Encrypts the message using AES encryption."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Padding message to make it multiple of block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return iv + ciphertext

def decrypt(ciphertext, key):
    """Decrypts the ciphertext using AES decryption."""
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypting and then unpadding the plaintext
    padded_message = decryptor.update(actual_ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()
    return message.decode()

def main():
    key = generate_key()
    print("AES Encryption and Decryption Program")
    print("A 32-byte random key has been generated for you.")
    print(f"Key (Keep this secret): {key.hex()}")
    
    while True:
        print("\nOptions:")
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            message = input("Enter the message to encrypt: ")
            encrypted_message = encrypt(message, key)
            print(f"Encrypted message (in hex): {encrypted_message.hex()}")
        elif choice == '2':
            encrypted_message_hex = input("Enter the encrypted message (in hex): ")
            encrypted_message = bytes.fromhex(encrypted_message_hex)
            decrypted_message = decrypt(encrypted_message, key)
            print(f"Decrypted message: {decrypted_message}")
        elif choice == '3':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()
