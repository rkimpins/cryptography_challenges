"""Two Time Pad Solver

This script attempts to break a Two Time Pad, or more generally, an N Time Pad

This program uses interactive crib dragging, as well as some complex rules to
filter results to only ones that could be english words. I originally learned
about crib dragging from
https://crypto.stackexchange.com/questions/2249/how-does-one-attack-a-two-time-pad-i-e-one-time-pad-with-key-reuse

This was inspired by working through the course "Cryptography I" by Stanford 
University on Coursera. This course can be found at 
https://www.coursera.org/learn/crypto?, and was available on May 7th, 2020.

This file can also be imported as a module, and contains the following useful function
    * xor_strings - xor strings of different length
    * string_to_hex - convert from string to hex
    * hex_to_string - convert from hex to string
    * crib_drag - run crib dragger on two ciphers
    * crib_drag_all_ciphers - run crib dragger on all ciphers
    * match_cribbed_to_words - find possible matches for a segement of text
    * interactive_solver - start solved for N time pad
"""


import binascii
import itertools
import re
import json


# Words is a list of words, seperated by a newline
file = open("words.txt", "r")
GLOBAL_LIST_OF_AMERICAN_ENGLISH_WORDS = [x.strip() for x in file.readlines()]
file.close()

#Common english words used for cribbing
#https://en.wikipedia.org/wiki/Most_common_words_in_English
GLOBAL_COMMON_ENGLISH_WORDS = ["the", "be", "to", "of", "and", "a", "in", "that", "have", "I", "it", "for", "not", "on", "with", "he", "as", "you", "do", "at", "this", "but", "his", "by", "from", "they", "we", "say", "she", "or", "an", "will", "my", "one", "all", "would", "there", "their", "what", "so", "up", "out", "if", "about", "who", "get", "which", "go", "me", "when", "make", "can", "like", "time", "no", "just", "him", "know", "take", "people", "into", "year", "your", "good", "some", "could", "them", "see", "other", "than", "then", "now", "look", "only", "come", "its", "over", "think", "also", "back", "after", "use", "two", "how", "our", "work", "first", "well", "way", "even", "new", "want", "because", "any", "these", "give", "day", "most", "us", "her"]

# Small Slant from http://www.patorjk.com/software/taag/
GLOBAL_INTRO = """
  _____    _ __     ___
 / ___/___(_) /    / _ \_______ ____ ____ ____ ____
/ /__/ __/ / _ \  / // / __/ _ `/ _ `/ _ `/ -_) __/
\___/_/ /_/_.__/ /____/_/  \_,_/\_, /\_, /\__/_/
                               /___//___/
"""


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

def regex_is_part_of_word(string: str) -> [str]:
    """Checks if a regex string could be part of an english word

    Depending on the regex provided, our string can appear at the end, start, or
    middle of an english word. Case is ignored

    Parameters
    ----------
    string : str
        the string to check

    Returns
    -------
    list(str)
        list of words that could match the provided string
    """

    p = re.compile(string, re.IGNORECASE)
    matches = []
    for word in GLOBAL_LIST_OF_AMERICAN_ENGLISH_WORDS:
        m = p.match(word)
        if m:
            matches.append(word)
    return matches

def convert_cribbed_to_regex(string: str) -> list:
    """Converts a resulting string from cribbing to a format to regex check against dictionary

    The string is divided by spaces. Depending on where each resulting string
    appears, they may appear at a different point of an english word. For 
    example: "and that is", "and" can be the end of a word, "that" must be an
    exact match, and "is" could be the beginning of a word". Another example 
    " ant" must be the start of a word, because of the leading space. Using
    this information, regex symbols are added to reflect the positions it can
    appear at in a word.

    Parameters
    ----------
    string : str
        the string to convert to a format appropriate for regex

    Returns
    -------
    list
        list of regex words to check against a dictionary
    """

    #TODO what happens when we have multiple spaces?
    # Split into individual words
    crib_split = string.split(" ")

    # If only 1 word, must be contained within a word
    if len(crib_split) == 1:
        crib_split[0] = ".*" + crib_split[0] + ".*"
    elif len(crib_split) == 2:
        # Either we have a leading/trailing space, or two words
        if crib_split[0] == "":
            crib_split[1] = "^" + crib_split[1] + ".*"
        elif crib_split[1] == "":
            crib_split[0] = ".*" + crib_split[0] + "$"
        else:
            crib_split[0] = ".*" + crib_split[0] + "$"
            crib_split[1] = "^" + crib_split[1] + ".*"
    elif len(crib_split) >= 3:
        # Inner words are all exact matches, outer words depend on spaces
        for index in range(1, len(crib_split)-1):
            crib_split[index] = "^" + crib_split[index] + "$"
        if crib_split[0] != "":
            crib_split[0] = ".*" + crib_split[0] + "$"
        if crib_split[-1] != "":
            crib_split[-1] = "^" + crib_split[-1] + ".*"
    # Remove empty strings
    crib_split = list(filter(lambda x: x != "", crib_split))
    return crib_split

def contains_illegal_symbols(string: str) -> bool:
    """Checks if the string contains symbols that suggest it isn't the message

    Currently, if the string contains anything other thatn alpha characters and
    spaces, we reject it. This is primarily because of collisions with our
    regular expression. We would like to eventually allow common symbols like 
    . , ! ? ' " etc. Regex would need to be sanitized or escaped.


    Parameters
    ----------
    string : str
        the string to check

    Returns
    -------
    bool
        true iff string does not contain the symbols
    """

    for char in string:
        if not str.isalpha(char) and char not in [" "]:
            return True
    return False

def match_cribbed_to_words(string: str) -> [[str]]:
    """Generate all possible matches against english words for a string

    A crib result will be a string. If it is gibberish, liek "d*3J0fS", we
    reject it. If it appears like some sort of text segment, like "ove ant",
    we check each segment of a word ("ove", "ant") to see if it is could possibly
    be a word. If every segment could in fact be part of a an english word, we
    return the possible matches. It is important to note that this method will
    automatically examples that contain words not contained in our dictionary
    (like user invented words), and currently rejects anything flagged by
    contains_illegal_symbols.

    Parameters
    ----------
    string : str
        the string to check against an english dictionary

    Returns
    -------
    list(list)
        a list of lists. Each list has all possible matches for one of the segements
    """

    total = 0
    multi_word_matches = []

    #TODO implement allowing common punctuation to appear

    # Reject results that 
    if contains_illegal_symbols(string):
        return []

    crib_split = convert_cribbed_to_regex(string)

    # Check that each segment could be part of a word
    for segment in crib_split:
        match = regex_is_part_of_word(segment)
        if match:
            multi_word_matches.append(match)
        else:
            return False
    return multi_word_matches

def decrypt_section(crib: str, index: int, cipher1: str, cipher2: str, target: str) -> (str, str):
    """Use a confirmed crib of two ciphers to decrypt the target

    Given two ciphers and a crib at an index that we suspect one of them
    contains, trys to calculate the key and decrypt the target. Since
    c xor m1 xor m1 = c, c xor m2 xor m2 = c, and our crib is either m1
    or m2, by xoring against both ciphers, one of our results is the
    key, assuming the crib is correct. This key can be used to decrypt the
    target.

    Parameters
    ----------
    crib : str
        the crib, which is the string we are guessing appears in the cipher
    index: int
    cipher1 : [str]
        the first cipher we found the crib on
    cipher2 : [str]
        the second cipher we found the crib on
    target : str
        the target cipher we want to decrypt

    Returns
    -------
    (str, str):
        a tuple of two strings, where each string is an attempted decryption
    """

    # Calculate the key from each
    key1 = xor_strings(string_to_hex(crib), cipher1[index:])
    key2 = xor_strings(string_to_hex(crib), cipher2[index:])
    # Use each key to decrypt the target
    result1 = hex_to_string(xor_strings(target[index:], key1))
    result2 = hex_to_string(xor_strings(target[index:], key2))
    # Return both attempted decryptions
    return (result1, result2)

def print_solution(solution: [str], max_width = None):
    """Pretty print the current solution

    Parameters
    ----------
    solution: [str]
        list of characters in the solution. Unguessed positions are "_"
    max_width: int
        the maximum number of characters to show on each line

    Returns
    -------
    (str, str):
        a tuple of two strings, where each string is an attempted decryption
    """

    if max_width == None:
        print("".join(solution))
    elif len(solution) <= max_width:
        print("".join(solution))
    else:
        print("".join(solution[0:max_width]))
        print_solution(solution[max_width:], max_width)

def print_help(topic: str):
    """Print help for the user depending on the topic

    Parameters
    ----------
    topic: str
        the topic the user needs help with. Determines what help message will be printed
    """

    # User needs help choosing a crib
    if topic == "crib":
        print("""Help:\nA crib is a word that we suspect would appear in either one of our cipher texts,\nor our target. A common strategy is to guess common english words as the crib,\nand check that the output makes sense. If we have part of a word decrypted, it is\na good choice to guess the rest of the word as the crib. Here are some of the\nmost common english words to use as cribs. Don't forget to try surrounding them\nwith spaces to maximizes the number of decrypted characters""")
        # Print common words with their ranking in a readable way
        print("Rank | Word")
        for index, word in enumerate(GLOBAL_COMMON_ENGLISH_WORDS):
            print("{:<20}".format(f"[({index+1}) {word}]"), end='')
            if (index + 1) % 5 == 0:
                print("")
        print("")

    elif topic == "crib or result":
        print("""HELP:\nShould we insert our chosen crib or the result of cribbing into our target? It\ncan be tricky to decide if it is the crib or the result of crib dragging which is\nthe solution to our target. If we have multiple ciphers, this becomes a bit\neasier. If the crib result makes sense for multiple cipher combinations at the\nexact same index, then the crib is probably the solution to our target. If the\ncrib result only makes sense for a single cipher, then it is probably the result\nwhich is the solution to our target. Additionally, if we already have a partially\nsolved target, and either our crib or result matches the partial solution, then\nthat is probably the solution. This is an art, not a science, so try a couple of\nthings. If you want to see all the possible dictionary matches for the result of the crib, use the expand matches command""")

def interactive_solver(ciphers: [str], target: str):
    """An interactive solver users run to solve a two time pad

    Iteratively tries to solve the two time pad. First asks the user for a crib
    and runs it against the different ciphers. Then asks the user to choose a
    result which seems like it would be the original message. Users have to
    choose whether the crib or the resulting text belongs in the target. If
    multiple cipher pairings at the same index result in what appears to be the
    original text of the message, then the crib is probably the solution for
    the target. Otherwise it is the resulting text. Some additional features
    are a help menu, common cribbing words, and TODO an option to display the
    possible matching words

    Parameters
    ----------
    ciphers : [str]
        list of ciphers, all encryted with the same key. Lengths can vary
    target : str
        the target cipher we are wanting to decrypt
    """

    print(GLOBAL_INTRO)

    solution = ["_" for x in range(len(target)//2)]
    while(True):
        # Display current solution
        print_solution(solution, max_width = 30)
        crib = input("Enter a crib [:q to quit, :h to get help]):")
        if crib == ":q":
            break
        if crib == ":h":
            print_help("crib")
            continue
        matches = crib_drag_all_ciphers(crib, ciphers, target)
        print("(Cipher, Index, Result)")
        for pos, match in enumerate(matches):
            print(f"[{pos}] {match[0:3]}")

        # If no matches, ask for another crib
        if len(matches) == 0:
            continue

        # Select a crib dragging result
        index = input("Choose an index to match, or enter None:")
        if index != "None":
            index = int(index)
            #TODO Make this clearer
            answer = input("Is it the crib or the result that matches the target [crib, target, expand matches, :h to get help]:")
            if answer == "crib":
                for pos, char in enumerate(crib):
                    solution[matches[index][1] + pos] = char
            elif answer == "target":
                for pos, char in enumerate(matches[index][2]):
                    solution[matches[index][1] + pos] = char
            elif answer == "expand matches":
                print("Printing suggested matches")
                print(matches[index][3])
            elif answer == ":h":
                print_help("crib or result")
            else:
                print("Invalid input")

def main():
    # Get ciphers from file
    json_data = open('ciphers.txt')
    json_obj = json.load(json_data)
    ciphers = json_obj["ciphers"]
    target = json_obj["target"]

    interactive_solver(ciphers, target)

if __name__ == "__main__":
    main()
