import binascii
import itertools
import re
import json


#https://crypto.stackexchange.com/questions/2249/how-does-one-attack-a-two-time-pad-i-e-one-time-pad-with-key-reuse
#Explanation of how to solve two time pad with crib dragging


# Words is a list of words, seperated by a newline
file = open("words.txt", "r")
GLOBAL_LIST_OF_AMERICAN_ENGLISH_WORDS = [x.strip() for x in file.readlines()]
file.close()

#Common english words used for cribbing
#https://en.wikipedia.org/wiki/Most_common_words_in_English
GLOBAL_COMMON_ENGLISH_WORDS = ["the", "be", "to", "of", "and", "a", "in", "that", "have", "I", "it", "for", "not", "on", "with", "he", "as", "you", "do", "at", "this", "but", "his", "by", "from", "they", "we", "say", "she", "or", "an", "will", "my", "one", "all", "would", "there", "their", "what", "so", "up", "out", "if", "about", "who", "get", "which", "go", "me", "when", "make", "can", "like", "time", "no", "just", "him", "know", "take", "people", "into", "year", "your", "good", "some", "could", "them", "see", "other", "than", "then", "now", "look", "only", "come", "its", "over", "think", "also", "back", "after", "use", "two", "how", "our", "work", "first", "well", "way", "even", "new", "want", "because", "any", "these", "give", "day", "most", "us", "her"]


def xor_strings(a: str, b: str) -> str:
    """Xors two hex strings of different length

    If the two strings are of different lengths, will only perform xor to the
    end of the shortest string. The rest of the other string is ignored

    Parameters
    ----------
    a : str
        first hex string
    b : str
        second hex string

    Returns
    -------
    str

        an int representing how good of a choice letter as a percentage difference
        a string of the best diagraph used
    """

    min_length = min(len(a), len(b))
    res = ""
    for index in range(min_length):
        res += hex(int(a[index],16) ^ int(b[index],16))[2:]
    return res

def string_to_hex(x: str) -> str:
    """Converts a character string to a hex string

    This implementation uses ISO-8859-1 since we expect to get none ascii or
    utf-8 symbols from our xor operations.

    Parameters
    ----------
    x : str
        character string to be converted to hex

    Returns
    -------
    str
        hex string
    """

    x = x.encode('ISO-8859-1')
    return str(binascii.hexlify(x), 'ISO-8859-1')

def hex_to_string(x: str) -> str:
    """Converts a hex string to a character string

    This implementation uses ISO-8859-1 since we expect to get none ascii or
    utf-8 symbols from our xor operations.

    Parameters
    ----------
    x : str
        hex string to be converted to characters

    Returns
    -------
    str
        character string
    """

    return str(binascii.unhexlify(x), 'ISO-8859-1')

def crib_drag_single_index(crib: str, index: int, xor_messages: str) -> str:
    """Crib drags on a specific index of a ciphered message

    Given a crib and and xored message, performs a single step of crib dragging
    by xoring on that index and returning the result. xor_messages should be 
    the xor of two messages encrypted with the same key

    Parameters
    ----------
    crib : str
        the crib, which is the string we are guessing appears in the cipher
    index : int
        the index to run this step of crib dragging on
    xor_messages : str
        the hex string for the xor of two ciphers

    Returns
    -------
    str
        result of single step of crib dragging as a character string
    """

    index *= 2
    #TODO break this line up
    return hex_to_string(xor_strings(string_to_hex(crib), xor_messages[index: index+len(crib)*2]))

def crib_drag(crib: str, xor_messages: str, cipher_num: int) -> [(int, int, str, [str])]:
    """Perform crib dragging on a single message, returning appropriate results

    Given a crib, an xored message, and the index of the cipher it originates
    from, performs crib dragging by call crib_drag_single_index at each
    possible position. Given a xor_message of reasonably length, the result
    of crib dragging would be too large to easily parse, so results are
    filtered automatically to only show results that could reasonably be an
    english text message. This is clarified and implemented in the functions:
    contains_illegal_symbols, convert_cribbed_to_regex, regex_is_part_of_word

    Parameters
    ----------
    crib : str
        the crib, which is the string we are guessing appears in the cipher
    xor_messages : str
        the hex string for the xor of two ciphers encrypted with the same key
    cipher_num

    Returns
    -------
    list(int, int, str, list(str))
        returns all reasonable matches, in the format
        (cipher of origin, index of cipher, resulting text, list of matches)
        List of matches is the full text for the words that our crib result
        could match
    """

    crib_matches = []
    # Run across all indexes
    for index in range(len(xor_messages)//2 - len(crib)):
        res = crib_drag_single_index(crib, index, xor_messages)
        # Append to result if it could match english words
        matches = match_cribbed_to_words(res)
        if matches:
            crib_matches.append((cipher_num, index, res, matches))
    return crib_matches

def crib_drag_all_ciphers(crib: str, ciphers: [str], target: str) -> [(int, int, str, [str])]:
    """Perform crib dragging on each cipher with the target , returning appropriate results

    Given a crib and a list of ciphers encrypted with the same key, performs
    crib dragging on each cipher xored with the target. Returns the concatenation
    of the results from crib_drag. Results are filtered automatically to only
    show results that could reasonably be an english text message. This is
    clarified and implemented in the functions: contains_illegal_symbols,
    convert_cribbed_to_regex, regex_is_part_of_word.

    Parameters
    ----------
    crib : str
        the crib, which is the string we are guessing appears in the cipher
    ciphers : [str]
        list of ciphers, all encryted with the same key. Lengths can vary
    target : str
        the target cipher we are wanting to decrypt

    Returns
    -------
    list(int, int, str, list(str))
        returns all reasonable matches, in the format
        (cipher of origin, index of cipher, resulting text, list of matches)
        List of matches is the full text for the words that our crib result
        could match
    """

    all_crib_matches = []
    # Run every cipher against the target
    for index in range(len(ciphers)):
        xor_message = xor_strings(ciphers[index], target)
        crib_matches = crib_drag(crib, xor_message, index)
        all_crib_matches += crib_matches
    return all_crib_matches

def remove_punctuation(string: str) -> str:
    """Removes common english punctuation from a string

    Currently removes the following: .,?!

    Parameters
    ----------
    string : str
        the string to remove punctuation from

    Returns
    -------
    str
        the resulting string with the punctuation removed
    """

    for punctuation in ['.', ',', '?', '!']:
        string = string.replace(punctuation, '')
    return string

def contains_punctuation(string: str) -> bool:
    """Checks if a string contains punctuation

    Currently checks the following: .,?!

    Parameters
    ----------
    string : str
        the string to check punctuation from

    Returns
    -------
    bool
        true iff the string contains punctuation
    """

    for punctuation in ['.', ',', '?', '!']:
        if punctuation in string:
            return True
    return False


def regex_is_part_of_word(string):
    p = re.compile(string, re.IGNORECASE)
    matches = []
    for word in GLOBAL_LIST_OF_AMERICAN_ENGLISH_WORDS:
        m = p.match(word)
        if m:
            matches.append(word)
    return matches

def convert_cribbed_to_regex(crib_res):
    #TODO what happens when we have multiple spaces?
    crib_split = crib_res.split(" ")
    if len(crib_split) == 1:
        crib_split[0] = ".*" + crib_split[0] + ".*"
    elif len(crib_split) == 2:
        if crib_split[0] == "":
            crib_split[1] = "^" + crib_split[1] + ".*"
        elif crib_split[1] == "":
            crib_split[0] = ".*" + crib_split[0] + "$"
        else:
            crib_split[0] = ".*" + crib_split[0] + "$"
            crib_split[1] = "^" + crib_split[1] + ".*"
    elif len(crib_split) >= 3:
        for index in range(1, len(crib_split)-1):
            crib_split[index] = "^" + crib_split[index] + "$"
        if crib_split[0] != "":
            crib_split[0] = ".*" + crib_split[0] + "$"
        if crib_split[-1] != "":
            crib_split[-1] = "^" + crib_split[-1] + ".*"
    # Remove empty strings
    crib_split = list(filter(lambda x: x != "", crib_split))
    return crib_split

def contains_illegal_symbols(string):
    for char in string:
        #if not str.isalpha(char) and not char.isdigit() and char not in [" ",",",".","!","?","'",'"']:
        if not str.isalpha(char) and char not in [" "]:
            return True
    return False

def match_cribbed_to_words(crib_res):
    total = 0
    multi_word_matches = []

    #TODO make this play nice with normal punctuation .,!?
    #darn regex
    if contains_illegal_symbols(crib_res):
        #print(f"Illegal: {crib_res}")
        return []
    #if not str.isalpha(crib_res):
        #return []

    crib_split = convert_cribbed_to_regex(crib_res)

    # Check that each partial is a word
    for partial in crib_split:

        match = regex_is_part_of_word(partial)
        if match:
            multi_word_matches.append(match)
        else:
            return False
    return multi_word_matches

def decrypt_section(crib, index, ciphertext1, ciphertext2, target):
    key1 = xor_strings(string_to_hex(crib), ciphertext1[index:])
    key2 = xor_strings(string_to_hex(crib), ciphertext2[index:])
    result1 = hex_to_string(xor_strings(target[index:], key1))
    result2 = hex_to_string(xor_strings(target[index:], key2))
    print(result1)
    print(result2)

def interactive_solver(ciphers, target):
    solution = ["_" for x in range(len(target)//2)]
    while(True):
        print(solution)
        crib = input("Enter a crib (:q to quit):")
        if crib == ":q":
            break
        matches = crib_drag_all_ciphers(crib, ciphers, target)
        print("(Cipher, Index, Result)")
        for pos, match in enumerate(matches):
            print(f"[{pos}] {match}")

        if len(matches) == 0:
            continue

        index = input("Choose a matching index, or [None]:")
        if index != "None":
            index = int(index)
            ans = input("Is this solution with the target or the cipher [target, cipher]:")
            if ans == "target":
                for pos, char in enumerate(crib):
                    solution[matches[index][1] + pos] = char
            elif ans == "cipher":
                for pos, char in enumerate(matches[index][2]):
                    solution[matches[index][1] + pos] = char
            else:
                print("Invalid input")



def main():

    # Shorten match lists that are too long
    #for ind in range(len(matches)):
    #    if len(matches[ind]) > 10:
    #        matches[ind] = matches[ind][0:10]
    #        matches[ind].append("...")

    #TODO break lines > 80
    #TODO remove suerflous comments and prints

    #print(match_cribbed_to_words("robab"))

    #ciphertext_1 = "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e"
    #ciphertext_2 = "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f"
    #ciphertext_3 = "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb"
    #ciphertext_4 = "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa"
    #ciphertext_5 = "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070"
    #ciphertext_6 = "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4"
    #ciphertext_7 = "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce"
    #ciphertext_8 = "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3"
    #ciphertext_9 = "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027"
    #ciphertext_10 = "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83"
    #target = "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"
    json_data = open('ciphers.txt')
    json_obj = json.load(json_data)
    ciphers = json_obj["ciphers"]
    target = json_obj["target"]

    #ciphertexts = [ciphertext_1, ciphertext_2, ciphertext_3, ciphertext_4, ciphertext_5,
        #ciphertext_6, ciphertext_7, ciphertext_8, ciphertext_9, ciphertext_10]

    #crib_drag_all_ciphers(" the ", ciphertexts, target)
    #[0] (0, 13, 'ssage')
    #[1] (4, 60, 'alize')
    #[2] (5, 60, 'ecret')
    #[3] (6, 51, 'never')
    #[4] (6, 60, 'rnmen')

    #x = crib_drag("message", 11, xor_strings(ciphertext_1, target))
    #print(x)
    #matches = match_cribbed_to_words(x)
    #print(matches)

    #print(contains_illegal_symbols("bhba"))
    interactive_solver(ciphers, target)



    '''
    for a result of crib drag in cipher x and y
    for all x combinations, check that they match at that index
    for all y combinations, check that they match at that index
    if one of these is signifigant (like > 3, b/c my matcher is weak)
    Try decrypting the target and all the other strings using this thing
    '''
    '''
    Input a crib drag
    It returns possible sections that it could have come from
    '''
    '''
    Make this interactive!!
    Input a crib
    Walks through every xored cipher, trying to find a matching index
    manually pick one
    Prints out all 10 + target after decrypting
    loop
    '''




    #TODO add hints for common words


if __name__ == "__main__":
    main()
