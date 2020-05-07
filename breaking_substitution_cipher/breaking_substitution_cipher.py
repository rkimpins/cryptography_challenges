"""Substitution cipher solver

This script breaks a message encrypted with a substitution cipher. It uses letter
and diagraph frequency analysis to complete this. 

Letter frequencies are taken from https://en.wikipedia.org/wiki/Letter_frequency
Diagraph frequency is taken from http://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/digraphs.html

This was inspired by working through the course "Cryptography I" by Stanford 
University on Coursera. This course can be found at 
https://www.coursera.org/learn/crypto?, and was available on May 7th, 2020.

This file can also be imported as a module, and contains the following useful function
    * decrypt_substitution_cipher - returns the decrypted message
"""

import unidecode
import collections
import diagraph_order
import random
import string

def clean_message(message: str) -> str:
    """Cleans up our message text for use in encryption

    Removes all punctuation, spaces, and converts accented and uppercase
    letters to lowercase unaccented letters

    Parameters
    ----------
    message : str
        the message that we would like to clean and encrypt

    Returns
    -------
    str
        cleaned up message
    """

    result = ""
    for char in message:
        if char.isalpha():
            result += char
    result = result.lower()
    result = unidecode.unidecode(result)
    return result.lower()

def encrypt_substitution_cipher(key: dict, message: str) -> str:
    """Encrypt a message using a simple substitution cipher

    Parameters
    ----------
    message : str
        the message that we would like to encrypt

    Returns
    -------
    str
        encrypted message
    """

    result = ""
    for letter in message:
        result += key[letter]
    return result

def letter_frequency(message: str) -> dict:
    """Finds the letter frequency from a message

    Parameters
    ----------
    message : str
        the message that we want the letter frequency of

    Returns
    -------
    dict
        (char, frequency) pairs
    """

    return collections.Counter(message)

def decode_e_t_a(encrypted_message: str) -> list:
    """Using frequency analysis, solves for e, t, and a in our encrypted message

    Parameters
    ----------
    encrypted_message : str
        the message that has been encrypted with a substitution cipher

    Returns
    -------
    list(3)
        the values of [e, t, a]
    """

    lf = letter_frequency(encrypted_message)
    lf = sorted(lf.items(), key=lambda kv: kv[1])
    lf.reverse()
    return [lf[0][0], lf[1][0], lf[2][0]]

def diagraph_frequency(message: str) -> dict:
    """Finds the diagraph frequency from a message

    An important thing to note is that our message has no spaces, so we are
    unable to differentiate diagraphs of the last and first letter of orders,
    which are not counted as diagraphs. Hopefully the frequency of these
    fake diagraphs are uncommon enough that our analysis will not fail

    Parameters
    ----------
    message : str
        the message that we want the diagraph frequency of

    Returns
    -------
    dict
        (diagraph, frequency) pairs
    """

    count = collections.Counter()
    for i in range(len(message)-1):
        count.update([message[i:i+2]])
    return count

def single_diagraph_search(diagraphs: list, pos: int, letter: chr, nots=[]) -> chr:
    """Solves for a single letter given its position in a diagraph to find

    Using a diagraph that appears frequently in our encrypted message, and
    using our knowledge of the expected frequency of diagraphs in english,
    if one of the letters in the diagraph is known, we can find the other.
    In this context, find means solving for its substitution

    Parameters
    ----------
    diagraphs : list
        (diagraph, frequency) tuples sorted in descending frequency in our message
    pos : int
        position of letter in diagraph
    letter : chr
        our choice of letter to solve for
    nots : list, optional
        list of letters that our solution can not be. Most likely because they
        are already found or assumed to be known

    Returns
    -------
    chr
        solution for our letter
    """

    for diagraph in diagraphs:
        if diagraph[0][pos] == letter and diagraph[0][1-pos] not in nots and diagraph[0][0] != diagraph[0][1]:
            return diagraph[0][1-pos]
    print(f"Failed to find {letter}")

def decrypt_substitution_cipher(encrypted_m: str) -> str:
    """Decodes an encryted message created with a substitution cipher.

    This solution uses letter and diagraph frequency analysis to break a
    susbtituion cipher.

    Parameters
    ----------
    encrypted_m: str
        the message encrypted by an unknown substitution cipher

    Returns
    -------
    (dict, str)
        dict : the key that was used for the encryption
        str : the decrypted message
    """

    # Solve for e,t,a
    key = {}
    [e,t,a] = decode_e_t_a(encrypted_m)
    key["e"] = e
    key["t"] = t
    key["a"] = a

    # Format diagrapha frequency as a list instead of dict
    diagraphs = diagraph_frequency(encrypted_m)
    diagraphs = sorted(diagraphs.items(), key=lambda kv: kv[1])
    diagraphs.reverse()

    # First attempt at manually ordering diagraph search
    # Using diagraphs th, er, an, in, nd, on, es, ou, ng, of, al, ve, pe, ly, co
    #to_find = ["h","r","n","i","d","o","s","u","g","f","l","v","y","c"]
    #to_use =  ["t","e","a","n","n","n","e","o","n","o","a","e","l","o"]
    #pos =     [ 0 , 0 , 0 , 1 , 0 , 1 , 0 , 0 , 0 , 0 , 0 , 1 , 0 , 1 ]

    # Use our module to find the best ordering of diagraphs
    (to_find, to_use, pos) = diagraph_order.generate_letter_order(["e","t","a"], ["b","c","d","f","g","h","i","j","k","l","m","n","o","p","q","r","s","u","v","w","x","y","z"])
    # Should return something like this
    #to_find = ["h","r","s","l","i","n","d","g","v","o","f","u","c","m","w","p","b","y","k","x","q","j"]
    #to_use = ["t","e","t","a","t","i","e","n","e","n","o","o","e","e","a","e","e","l","e","e","u","u"]
    #pos = [ 0 , 1 , 1 , 0 , 0 , 0 , 0 , 0 , 1 , 1 , 0 , 0 , 0 , 1 , 1 , 1 , 1 , 0 , 1 , 0 , 1 , 1 ]

    # Run each diagraph solution to solve for all letters
    for i in range(len(pos)):
        key[to_find[i]] = single_diagraph_search(diagraphs, pos[i], key[to_use[i]], key.values())

    # Find value for last key z
    for char in string.ascii_lowercase:
        if char not in key.values():
            key['z'] = char
            break


    # Reverse our key and decrypt the message
    reverse_key = {v: k for k, v in key.items()}

    # If a letter is missing for any reason, replace with _
    for char in string.ascii_lowercase:
        if char not in reverse_key.keys():
            reverse_key[char] = "_"

    print(key)
    decrypted_message = ""
    for char in encrypted_m:
        decrypted_message += reverse_key[char]

    return key, decrypted_message

def create_encryption_key() -> dict:
    """Creates a random substitution key to encrypt the message

    Returns
    -------
    dict
        key value pairs where each is a lowercase alpha value
    """

    keys = list(string.ascii_lowercase)
    values = keys.copy()
    random.shuffle(values)
    key = {k: v for k,v in zip(keys, values)}
    return key

def main():
    """Encrypts a message loaded from file, then decrypts the message
    """

    filename = "message.txt"
    key = create_encryption_key()
    key = {"a":"z", "b":"e", "c":"b", "d":"r", "e":"a", "f":"s", "g":"c", 
            "h":"d", "i":"f", "j":"g", "k":"h", "l":"i", "m":"j", "n":"k", 
            "o":"l", "p":"m", "q":"n", "r":"o", "s":"p", "t":"q", "u":"t", 
            "v":"u", "w":"v", "x":"w", "y":"x", "z":"y"}
    # Read message from file
    f = open(filename,"r")
    message = f.read()
    message = clean_message(message)

    # Encrypt
    encrypted_message = encrypt_substitution_cipher(key, message)

    # Decrypt
    decryption_key, decrypted_message = decrypt_substitution_cipher(encrypted_message)
    print("Original message: ", message[0:100])
    print("Decrypted message:", decrypted_message[0:100])

    print(key, decryption_key)
    # How accurate were we?
    total = 0
    for char in string.ascii_lowercase:
        if key[char] == decryption_key[char]:
            total += 1
    print(f"Algorithm correctly decrypted {total} out of 26 letters")


if __name__ == "__main__":
    main()
