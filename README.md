# Secret Communication Tool
#### Video Demo:  <https://youtu.be/IKF7koEHTAg?si=ltgTOB_D1ErT98FE>
#### Description:
The Secret Communication Tool is a Python program designed for secure messaging and information hiding. It incorporates various cryptographic techniques to encode messages in images and perform text encryption and decryption. The tool also provides Caesar Cipher functionality for an additional layer of text obfuscation.

## Project Overview

The project consists of a command-line tool with the following features:

- `Image Encoding:` Encode a message into an image (.PNG) using the Steganography technique.
- `Image Decoding:` Decode a hidden message from an encoded image (.PNG).
- `Text Encryption:` Encrypt text using AES-256 in CFB mode with key derivation from a password.
- `Text Decryption:` Decrypt text encrypted with the tool's encryption function.
- `Caesar Cipher:` Perform Caesar Cipher on text for basic encryption.

## Project Structure

- `project.py:` Main script containing the implementation.
- `test_project.py:` Unit tests for the project functions.
- `requirements.txt:` List of pip-installable libraries required for the project.

## How to Use

To use the tool, run the project.py script with appropriate command-line arguments for the desired functionality. Detailed instructions are provided in the command-line help messages.

### Usage Examples
```bash
# Encode a message into an image
python project.py encode -m "Hello, secret world!" -i input_image.png -o output_image_encoded.png

# Decode a hidden message from an encoded image
python project.py decode -i output_image_encoded.png

# Encrypt text using a custom key
python project.py encrypt -t "Sensitive information" -k secret_key -o encrypted_text.txt

# Decrypt encrypted text using the same key
python project.py decrypt -i encrypted_text.txt -k secret_key

# Cypher text with Caeser Cypher with a custom shift
python project.py caeser -n 3 -m "Cypher this message with a 3 positive shift"

# Cypher text with Caeser Cypher with a custom shift
python project.py caeser -n 3 -f file.txt
```

## Design Choices

The tool utilizes established cryptographic libraries such as PyCryptodome and stepic for image encoding. It follows best practices for key derivation and encryption to ensure secure communication. The command-line interface allows for easy integration into scripts and applications.

## Author

- Salah Al Shayah
- Lebanon

Feel free to reach out if you have any questions or suggestions for improvement at salah.alshayah@lau.edu!
