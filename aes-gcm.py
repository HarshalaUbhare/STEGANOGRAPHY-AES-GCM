import base64
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import cv2
from PIL import Image
import numpy as np  # Don't forget to import numpy

HASH_NAME = "SHA512"
IV_LENGTH = 12
ITERATION_COUNT = 65535
KEY_LENGTH = 32
SALT_LENGTH = 16
TAG_LENGTH = 16


def encrypt(password, plain_message, iv):
    salt = get_random_bytes(SALT_LENGTH)
    secret = get_secret_key(password, salt)

    cipher = AES.new(secret, AES.MODE_GCM, iv)

    encrypted_message_byte, tag = cipher.encrypt_and_digest(
        plain_message.encode("utf-8")
    )
    cipher_byte = salt + iv + encrypted_message_byte + tag

    encoded_cipher_byte = base64.b64encode(cipher_byte)

    return bytes.decode(encoded_cipher_byte)


def decrypt(password, cipher_message):
    decoded_cipher_byte = base64.b64decode(cipher_message)

    salt = decoded_cipher_byte[:SALT_LENGTH]
    iv = decoded_cipher_byte[SALT_LENGTH : (SALT_LENGTH + IV_LENGTH)]
    encrypted_message_byte = decoded_cipher_byte[
        (IV_LENGTH + SALT_LENGTH) : -TAG_LENGTH
    ]
    tag = decoded_cipher_byte[-TAG_LENGTH:]
    secret = get_secret_key(password, salt)
    cipher = AES.new(secret, AES.MODE_GCM, iv)

    decrypted_message_byte = cipher.decrypt_and_verify(encrypted_message_byte, tag)
    return decrypted_message_byte.decode("utf-8")


def get_secret_key(password, salt):
    return hashlib.pbkdf2_hmac(
        HASH_NAME, password.encode(), salt, ITERATION_COUNT, KEY_LENGTH
    )


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


def encode():
    img_name = input("\nEnter image name:")
    image = cv2.imread(img_name)
    img = Image.open(img_name, 'r')
    w, h = img.size
    data = input("\nEnter message:")
    if len(data) == 0:
        raise ValueError("Empty data")
    secret_key = input("\nEnter secret key:")
    enc_img = input("\nEnter encoded image name:")
    iv = get_random_bytes(IV_LENGTH)
    cipher_text = encrypt(secret_key, data, iv)
    enc_data = hidedata(image, cipher_text)
    cv2.imwrite(enc_img, enc_data)
    img1 = Image.open(enc_img, 'r')
    img1 = img1.resize((w, h), Image.BILINEAR)

    if w != h:
        img1.save(enc_img, optimize=True, quality=65)
    else:
        img1.save(enc_img)


def decode():
    img_name = input("\nEnter Image name : ")
    image = cv2.imread(img_name)
    img = Image.open(img_name, 'r')
    secret_key = input("\nEnter secret key:")
    msg = find_data(image, secret_key)
    return msg


def find_data(img, secret_key):
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

    decrypted_text = decrypt(secret_key, readable_data[:-2])
    return decrypted_text


def stegnography():
    x = 1
    while x != 0:
        print('''\nImage steganography
        1. Encode
        2. Decode''')
        u_in = int(input("\nEnter your choice:"))
        if u_in == 1:
            encode()
        else:
            ans = decode()
            print("\nYour message:", ans)
        x = int(input("\nEnter 1 to continue otherwise 0:"))


stegnography()
