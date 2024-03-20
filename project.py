from PIL import Image
import argparse
import stepic
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Constants
SALT = b'\xa8\x90\xf7\xc2~\xf6\x87\x8b\xcc\xd7\xf4\x9d\xdf:\xc7\xd5'

def encode_message(message, image_path, output_path):
    try:
        with Image.open(image_path) as original_image:
            if original_image.format != 'PNG':
                raise ValueError("Input image must be in PNG format.")
            message_bytes = message.encode('utf-8')
            encoded_image = stepic.encode(original_image, message_bytes)
            encoded_image.save(output_path)
    except FileNotFoundError:
        print(f"Error: Input image '{image_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

def decode_message(image_path):
    """Decode a message from an image using stepic."""
    encoded_image = Image.open(image_path)
    decoded_message_bytes = stepic.decode(encoded_image)
    decoded_message = decoded_message_bytes.encode('utf-8').decode('utf-8')
    return decoded_message

def derive_key_from_password(password, salt):
    """Derive a key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    return key

def encrypt_text(text, password, salt):
    """Encrypt text using AES-256 in CFB mode."""
    key = derive_key_from_password(password, salt)
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(text.encode('utf-8')) + encryptor.finalize()
    return b64encode(iv + cipher_text).decode('utf-8')

def decrypt_text(cipher_text, password, salt):
    """Decrypt text using AES-256 in CFB mode."""
    key = derive_key_from_password(password, salt)
    data = b64decode(cipher_text)
    iv, cipher_text = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(cipher_text) + decryptor.finalize()
    return decrypted_text.decode('utf-8')

def caesar_cipher(text, shift):
    """Perform Caesar Cipher on text."""
    result = ''
    for char in text:
        if char.isalpha():
            offset = ord('a') if char.islower() else ord('A')
            result += chr((ord(char) - offset + shift) % 26 + offset)
        else:
            result += char
    return result

def main():
    parser = argparse.ArgumentParser(description='Secret Communication Tool')
    subparsers = parser.add_subparsers(dest='command', help='Choose a command')

    # Image Encoding
    encode_parser = subparsers.add_parser('encode', help='Encode a message into an image')
    encode_parser.add_argument('-m', '--message', required=True, help='The message to encode')
    encode_parser.add_argument('-i', '--input', required=True, help='Input image path')
    encode_parser.add_argument('-o', '--output', required=True, help='Output image path')

    # Image Decoding
    decode_parser = subparsers.add_parser('decode', help='Decode a message from an image')
    decode_parser.add_argument('-i', '--input', required=True, help='Input image path')

    # Text Encryption
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt text')
    encrypt_parser.add_argument('-t', '--text', required=True, help='Text to encrypt')
    encrypt_parser.add_argument('-k', '--key', required=True, help='Encryption key')
    encrypt_parser.add_argument('-o', '--output', required=True, help='Output file path for encrypted text')

    # Text Decryption
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt text')
    decrypt_parser.add_argument('-i', '--input', required=True, help='Input file path with encrypted text')
    decrypt_parser.add_argument('-k', '--key', required=True, help='Decryption key')

    # Caeser Cyphering
    caeser_parser = subparsers.add_parser('caeser', help='Perform Caeser Cyphering')
    caeser_parser.add_argument('-n', '--shift', type=int, required=True, help='Shift value for Caeser Cypher')
    caeser_parser.add_argument('-m', '--message', help='Text to perform Caeser Cyphering')
    caeser_parser.add_argument('-f', '--file', help='File path with text to perform Caeser Cyphering')

    args = parser.parse_args()


    if not hasattr(args, 'command') or args.command is None:
        parser.print_help()
        return

    try:
        if args.command == 'encode':
            encode_message(args.message, args.input, args.output)
        elif args.command == 'decode':
            print(f"The decoded message is:\n{decode_message(args.input)}")
        elif args.command == 'encrypt':
            encrypted_text = encrypt_text(args.text, args.key, SALT)
            with open(args.output, 'w') as file:
                file.write(encrypted_text)
        elif args.command == 'decrypt':
            with open(args.input, 'r') as file:
                encrypted_text = file.read()
            decrypted_text = decrypt_text(encrypted_text, args.key, SALT)
            print('Decrypted Text:', decrypted_text)
        elif args.command == 'caeser':
            if args.message:
                result = caesar_cipher(args.message, args.shift)
                print('Caesar Ciphered Text:', result)
            elif args.file:
                with open(args.file, 'r') as file:
                    text = file.read()
                result = caesar_cipher(text, args.shift)
                print('Caesar Ciphered Text from File:', result)
            else:
                print('Please provide either a message or a file for Caesar Ciphering.')
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
