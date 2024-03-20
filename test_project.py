import pytest
from project import encode_message, decode_message, encrypt_text, decrypt_text, caesar_cipher

SALT = b'\xa8\x90\xf7\xc2~\xf6\x87\x8b\xcc\xd7\xf4\x9d\xdf:\xc7\xd5'

def test_encode_message():
    input_message = "Hello, secret world!"
    input_image_path = "encode_input_demo.png"
    output_image_path = "encode_output_demo.png"

    # Perform encoding
    encode_message(input_message, input_image_path, output_image_path)

    # Perform decoding and check if the original message is obtained
    decoded_message = decode_message(output_image_path)
    assert decoded_message == input_message

def test_encrypt_decrypt_text():
    input_text = "Sensitive information"
    key = "secret_key"

    # Perform encryption
    encrypted_text = encrypt_text(input_text, key, SALT)

    # Perform decryption and check if the original text is obtained
    decrypted_text = decrypt_text(encrypted_text, key, SALT)
    assert decrypted_text == input_text

def test_caesar_cipher():
    input_text = "Cipher this message with a 3 positive shift"
    shift = 3

    # Perform Caesar Cipher
    ciphered_text = caesar_cipher(input_text, shift)

    # Perform reverse Caesar Cipher and check if the original text is obtained
    deciphered_text = caesar_cipher(ciphered_text, -shift)
    assert deciphered_text == input_text

if __name__ == "__main__":
    pytest.main()
