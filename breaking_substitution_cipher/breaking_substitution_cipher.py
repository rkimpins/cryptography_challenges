import unidecode
import collections
import diagraph_order

def clean_message(message):
    result = ""
    for char in message:
        if char.isalpha():
            result += char
    result = result.lower()
    result = unidecode.unidecode(result)
    return result.lower()

def encrypt_substitution_cipher(key,message):
    result = ""
    for letter in message:
        result += key[letter]
    return result

def letter_frequency(message):
    return collections.Counter(message)

def decode_e_t_a(encrypted_message):
    lf = letter_frequency(encrypted_message)
    lf = sorted(lf.items(), key=lambda kv: kv[1])
    lf.reverse()
    return [lf[0][0], lf[1][0], lf[2][0]]

def diagraph_frequency(message):
    count = collections.Counter()
    for i in range(len(message)-1):
        count.update([message[i:i+2]])
    return count


def single_diagraph_search(diagraphs, pos, letter, nots=[]):
    print("function args:", pos, letter, nots)
    for diagraph in diagraphs:
        if diagraph[0][pos] == letter and diagraph[0][1-pos] not in nots and diagraph[0][0] != diagraph[0][1]:
            print("diagraph:", diagraph)
            return diagraph[0][1-pos]
    print(f"Failed to find {letter}")

def decrypt_substitution_cipher(encrypted_m):
    key = {}
    [e,t,a] = decode_e_t_a(encrypted_m)
    key["e"] = e
    key["t"] = t
    key["a"] = a
    print(key)

    diagraphs = diagraph_frequency(encrypted_m)
    diagraphs = sorted(diagraphs.items(), key=lambda kv: kv[1])
    diagraphs.reverse()

    #key["h"] = single_diagraph_search(diagraphs, 0, key["t"]) 
    print(key)
    # Manual method I attempted
    # Using diagraphs th, er, an, in, nd, on, es, ou, ng, of, al, ve, pe, ly, co
    #to_find = ["h","r","n","i","d","o","s","u","g","f","l","v","y","c"]
    #to_use =  ["t","e","a","n","n","n","e","o","n","o","a","e","l","o"]
    #pos =     [ 0 , 0 , 0 , 1 , 0 , 1 , 0 , 0 , 0 , 0 , 0 , 1 , 0 , 1 ]


    (to_find, to_use, pos) = diagraph_order.generate_letter_order(["e","t","a"], ["b","c","d","f","g","h","i","j","k","l","m","n","o","p","q","r","s","u","v","w","x","y","z"])
    # Should return
    #to_find = ["h","r","s","l","i","n","d","g","v","o","f","u","c","m","w","p","b","y","k","x","q","j"]
    #to_use = ["t","e","t","a","t","i","e","n","e","n","o","o","e","e","a","e","e","l","e","e","u","u"]
    #pos = [ 0 , 1 , 1 , 0 , 0 , 0 , 0 , 0 , 1 , 1 , 0 , 0 , 0 , 1 , 1 , 1 , 1 , 0 , 1 , 0 , 1 , 1 ]



    for i in range(len(pos)):
        key[to_find[i]] = single_diagraph_search(diagraphs, pos[i], key[to_use[i]], key.values())
        print(key)


def main():
    #https://en.wikipedia.org/wiki/Letter_frequency
    #http://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/digraphs.html
    filename = "message.txt"
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
    decrypt_substitution_cipher(message)


main()


