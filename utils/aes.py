import os

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ==========================================
# AES CONFIGURATION
# ==========================================

KEY_SIZE = 32          # AES-256
BLOCK_SIZE = 16        # AES Block Size

# ==========================================
# PAD DATA
# ==========================================

def pad(data):

    padding = BLOCK_SIZE - len(data) % BLOCK_SIZE

    return data + bytes([padding]) * padding

# ==========================================
# REMOVE PADDING
# ==========================================

def unpad(data):

    padding = data[-1]

    return data[:-padding]

# ==========================================
# ENCRYPT FILE
# ==========================================

def encrypt_file(input_file, output_file):

    # Generate AES-256 Key
    key = get_random_bytes(KEY_SIZE)

    # Create AES Cipher
    cipher = AES.new(
        key,
        AES.MODE_CBC
    )

    iv = cipher.iv

    # Read Original File
    with open(input_file, "rb") as file:

        plaintext = file.read()

    # Encrypt
    ciphertext = cipher.encrypt(
        pad(plaintext)
    )

    # Save IV + Ciphertext
    with open(output_file, "wb") as file:

        file.write(iv)

        file.write(ciphertext)

    return key

def unpad(data):

    padding = data[-1]

    return data[:-padding]


def decrypt_file(input_file, output_file, key):

    with open(input_file, "rb") as f:

        iv = f.read(16)

        ciphertext = f.read()

    cipher = AES.new(
        bytes.fromhex(key),
        AES.MODE_CBC,
        iv
    )

    plaintext = unpad(
        cipher.decrypt(ciphertext)
    )

    with open(output_file, "wb") as f:

        f.write(plaintext)

# ==========================================
# DECRYPT FILE
# ==========================================

def decrypt_file(input_file, output_file, key):

    # Convert hex string back to 32-byte key
    if isinstance(key, str):
        key = bytes.fromhex(key)

    with open(input_file, "rb") as f:

        iv = f.read(16)

        ciphertext = f.read()

    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv
    )

    plaintext = cipher.decrypt(ciphertext)

    padding = plaintext[-1]

    plaintext = plaintext[:-padding]

    with open(output_file, "wb") as f:

        f.write(plaintext)
# ==========================================
# GENERATE AES KEY
# ==========================================

def generate_key():

    return get_random_bytes(KEY_SIZE)