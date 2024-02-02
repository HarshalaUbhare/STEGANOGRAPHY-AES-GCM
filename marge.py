import os
import cv2
from PIL import Image
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64

def data2binary(data):
    if type(data) == str:
        p = ''.join([format(ord(i), '08b') for i in data])
    elif type(data) == bytes or type(data) == np.ndarray:
        p = [format(i, '08b') for i in data]
    return p

def hidedata(img, data):
    data += "$$"
    d_index = 0
    b_data = data2binary(data)
    len_data = len(b_data)

    for value in img:
        for pix in value:
            r, g, b = data2binary(pix)
            if d_index < len_data:
                pix[0] = int(r[:-1] + b_data[d_index])
                d_index += 1
            if d_index < len_data:
                pix[1] = int(g[:-1] + b_data[d_index])
                d_index += 1
            if d_index < len_data:
                pix[2] = int(b[:-1] + b_data[d_index])
                d_index += 1
            if d_index >= len_data:
                break
    return img

def find_data(img):
    bin_data = ""
    for value in img:
        for pix in value:
            r, g, b = data2binary(pix)
            bin_data += r[-1]
            bin_data += g[-1]
            bin_data += b[-1]

    all_bytes = [bin_data[i: i + 8] for i in range(0, len(bin_data), 8)]

    readable_data = ""
    for x in all_bytes:
        readable_data += chr(int(x, 2))
        if readable_data[-2:] == "$$":
            break
    return readable_data[:-2]

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

def encode():
    img_name = input("\nEnter image name: ")
    image = cv2.imread(img_name)
    img = Image.open(img_name, 'r')
    w, h = img.size
    data = input("Enter message: ")
    if len(data) == 0:
        raise ValueError("Empty data")
    enc_img = input("Enter encoded image name: ")
    
    # Get the user's secret key
    user_key = get_user_key()
    
    # Encrypt message using AES
    encrypted_message = encrypt_message(user_key, data.encode('utf-8'))
    
    # Embed the encrypted message into the image
    enc_data = hidedata(image, encrypted_message)
    
    # Save the encoded image
    cv2.imwrite(enc_img, enc_data)
    img1 = Image.open(enc_img, 'r')
    img1 = img1.resize((w, h), Image.BILINEAR)

    # Optimize with 65% quality
    if w != h:
        img1.save(enc_img, optimize=True, quality=65)
    else:
        img1.save(enc_img)

def decode():
    enc_img_name = input("\nEnter encoded image name: ")
    
    # Get the user's secret key
    user_key = get_user_key()
    
    # Read the encoded image
    image = cv2.imread(enc_img_name)
    
    # Extract the encrypted message using LSB steganography
    enc_message = find_data(image)
    
    # Decrypt the message using AES
    decrypted_message = decrypt_message(user_key, enc_message.encode('utf-8'))
    
    print("\nDecoded Message:", decrypted_message)

def steganography():
    x = 1
    while x != 0:
        print('''\nImage steganography
        1. Encode
        2. Decode''')
        u_in = int(input("\nEnter your choice: "))
        if u_in == 1:
            encode()
        elif u_in == 2:
            decode()
        else:
            print("Invalid choice. Please enter 1 or 2.")
        x = int(input("\nEnter 1 to continue, otherwise 0: "))

steganography()
