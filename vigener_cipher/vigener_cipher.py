"""Simple Vigner Cipher

Encrypts a message using a vigner cipher. More information on this cipher can 
be found at https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher

This file can also be imported as a module, and contains the following useful function
    * vigner_cipher - encrypts a message with a vigner cipher
"""

import string
import unidecode

def vigner_cipher(message: str, key: str) -> str:
    """Encypts a message using a vigner cipher

    Please note that this encrytion will only work with lowercase alpha
    characters. As such, all messages are automatically converted to this
    format, including removing non-alpha characters, and converting
    accented characters.


    Parameters
    ----------
    message : str
        the message that we would like to encrypt
    key ;str
        the key to encrypt by

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


    key = list(key)
    key_pos = 0
    message = list(message)
    for i in range(len(message)):
        message[i] = chr((ord(message[i]) + ord(key[i % len(key)]) - 2 * ord('a')) % 26 + ord('a'))

    return ''.join(message)

def test_vigner_cipher(message: str, key: str, result: str):
    """Tests our implementation of the caesar cipher

    Parameters
    ----------
    message : str
        the message that we would like to encrypt
    key ; str
        the key to encrypt by
    result : str
        the expected result of the encryption
    """

    if vigner_cipher(message, key) == result:
        print(f"vigner_cipher({message}, {key}) == {result}), Test Passed")
    else:
        print(f"vigner_cipher({message}, {key}) != {result}), Test Failed")
        print(f"Expected: {result}, Output: {vigner_cipher(message, key)}")

def main():
    message = string.ascii_lowercase
    test_vigner_cipher(message, "abc", "acedfhgikjlnmoqprtsuwvxzya")


if __name__ == "__main__":
    main()
