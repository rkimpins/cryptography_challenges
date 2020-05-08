"""Simple Ceasar Cipher

This file can also be imported as a module, and contains the following useful function
    * caesar_cipher - encrypts a message with a caesar_cipher
"""

import string
import unidecode

def caesar_cipher(message: str, shift: int) -> str:
    """Encypts a message using a caesar cipher

    Please note that this encrytion will only work with lowercase alpha
    characters. As such, all messages are automatically converted to this
    format, including removing non-alpha characters, and converting
    accented characters.


    Parameters
    ----------
    message : str
        the message that we would like to encrypt
    shift : int
        the shift amount to encrypt by

    Returns
    -------
    str
        the encrypted message
    """

    # Clean the message so it only contains lowercase letters
    cleaned_message = ""
    for char in message:
        if char.isalpha():
            cleaned_message += char
    cleaned_message = cleaned_message.lower()
    cleaned_message = unidecode.unidecode(cleaned_message)
    cleaned_message = cleaned_message.lower()
    message = cleaned_message

    new_message = ""
    for char in message:
        new_char = chr((ord(char) - ord('a') + shift) % (ord('z') - ord('a') + 1) + ord('a'))
        new_message += new_char
    return new_message

def test_caesar_cipher(message: str, shift: int, result: str):
    """Tests our implementation of the caesar cipher

    Parameters
    ----------
    message : str
        the message that we would like to encrypt
    shift : int
        the shift amount to encrypt by
    result : str
        the expected result of the encryption
    """

    if caesar_cipher(message, shift) == result:
        print(f"caesar_cipher({message}, {shift}) == {result}), Test Passed")
    else:
        print(f"caesar_cipher({message}, {shift}) != {result}), Test Failed")
        print(f"Expected: {result}, Output: {caesar_cipher(message, shift)}")

def main():
    message = string.ascii_lowercase
    # Empty string
    test_caesar_cipher("", 0, "")
    # Don't shift at all
    test_caesar_cipher(message, 0, message)
    # Shift by 1
    test_caesar_cipher(message, 1, "bcdefghijklmnopqrstuvwxyza")
    # Shift by 26, should be the same as shifting by 0
    test_caesar_cipher(message, 26, message)
    # Shift by 25
    test_caesar_cipher(message, 25, "zabcdefghijklmnopqrstuvwxy")
    # Uppercase letters
    test_caesar_cipher(message.upper(), 0, message)
    # Symbols
    test_caesar_cipher("@^$(%&*()#&_a()+{}:>,;,}<.?[", 0, "a")
    # Negative Shift
    test_caesar_cipher(message, -1, "zabcdefghijklmnopqrstuvwxy")

if __name__ == "__main__":
    main()
