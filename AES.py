import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64
def get_user_key():
    while True:
        user_key = input("Enter a 4-digit secret key: ")
        if len(user_key) == 4 and user_key.isdigit():
            return user_key.encode('utf-8')
        else:
            print("Invalid key. Please enter a 4-digit numeric key.")

def encrypt_message(key, message):
    key = key.ljust(16, b'\0')
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    encoded_message = base64.b64encode(iv + ciphertext).decode('utf-8')
    return encoded_message

def decrypt_message(key, encoded_message):
    key = key.ljust(16, b'\0')
    decoded_message = base64.b64decode(encoded_message)
    iv = decoded_message[:16]
    ciphertext = decoded_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    original_message = unpadder.update(decrypted_data) + unpadder.finalize()
    return original_message.decode('utf-8')

# Get the user's secret key
user_key = get_user_key()

# Example usage
message = input("Enter the message to be encrypted: ")
encoded_message = encrypt_message(user_key, message.encode('utf-8'))
print('Encrypted Message:', encoded_message)

decrypted_message = decrypt_message(user_key, encoded_message)
print('Decrypted Message:', decrypted_message)
