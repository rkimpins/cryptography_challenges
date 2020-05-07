"""Diagraph order generator

This script considers the frequency of different diagrahs in the english
language and generates the order that we would want to use them to decrypt
a substitution cipher. A diagraph is a two letter combination that appears
frequently in the english language, such as "th" 

To choose a good diagrah, we first need a letter that we know the substitution x
for, and a diagraph that is common enough to notice in some encryted text but
where the next instance that it could be mistaken for is statistically
significantly far away. This script attempts to iteratively find the best choice
for this, until all letters are known.

Diagraph frequencies are taken from 
http://practicalcryptography.com/media/cryptanalysis/files/english_bigrams_1.txt
and are stored as a json object (dict(diagraph : frequency)) in diagraph_frequency.txt

This file can also be imported as a module, and contains the following useful function
    * generate_letter_order - returns three formatted lists detailing diagraphs order
"""
import json

# Setup global variables that hold diagraph frequency information
json_data = open('diagraph_frequency.txt')
global_diagraph_freq = json.load(json_data)

global_diagraph_freq_list = sorted(global_diagraph_freq.items(), key=lambda kv: kv[1])
global_diagraph_freq_list.reverse()

global_total_diagraphs = sum(global_diagraph_freq.values())



def distance_to_next_match(diagraph: str, letter: chr, pos: int, unfound: list) -> (int,str):
    """Given a diagrah and letter, returns how distinct that diagraph is from other letters

    Parameters
    ----------
    diagraph : str
        a string consisting of two lowercase alpha characters
    letter : chr
        the letter of interest in the diagraph
    pos : int
        position of letter in diagraph
    unfound : list
        list of characters that have not yet been found

    Returns
    -------
    (int, str)
        an int representing how good of a choice letter as a percentage difference
        a string of the best diagraph used
    """

    if diagraph == None:
        return float("-inf"), ""
    min_val = float("inf")
    min_dia = ""
    dias = {}
    for c in unfound:
        if c == diagraph[1-pos] or c == letter:
            continue
        # Consider diagraphs where letter is in pos 0 or 1
        if pos:
            val = c+letter
        else:
            val = letter+c

        diff = global_diagraph_freq[diagraph] - global_diagraph_freq[val]
        if min_val > diff:
            min_val = diff
            min_dia = val

    return min_val / global_total_diagraphs * 100, min_dia


def min_distance_of_letter(letter: chr, found: list, unfound: list) -> (int,str):
    """Given a letter, finds the best value for it over all diagraphs

    Parameters
    ----------
    letter : chr
        the letter of interest in the diagraph
    unfound : list
        list of characters that have not yet been found
    found : list
        list of characters that have been found

    Returns
    -------
    (int, str)
        an int representing how good of a choice a letter is as a percentage 
        difference of occurences
        a string of the best diagraph used
    """

    # Find first matching diagraph for letter, either position
    for item in global_diagraph_freq_list:
        if item[0][0] == letter and item[0][1] in unfound:
            diagraph0 = None
            break
        if item[0][0] == letter and item[0][1] in found:
            diagraph0 = item[0]
            break
    for item in global_diagraph_freq_list:
        if item[0][1] == letter and item[0][0] in unfound:
            diagraph1 = None
            break
        if item[0][1] == letter and item[0][0] in found:
            diagraph1 = item[0]
            break

    (dist0, dist1_diagraph) = distance_to_next_match(diagraph0, letter, 0, unfound)
    (dist1, dist2_diagraph) = distance_to_next_match(diagraph1, letter, 1, unfound)
    if dist0 > dist1:
        return dist0, diagraph0
    else:
        return dist1, diagraph1

def best_choice_of_letter(found: list, unfound: list) -> (chr, str, int):
    """Given a list of found and unfound letters, returns the best letter to use

    Parameters
    ----------
    found : list
        list of characters that have been found
    unfound : list
        list of characters that have not yet been found

    Returns
    -------
    (chr, int, str)
        a character of the best letter to use
        a string of the best diagraph used
        an int representing how good of a choice a letter is as a percentage 
        difference of occurences
    """

    best_letter = ""
    max_val = float("-inf")
    best_dia = ""
    # Loop over unfound letters finding the best choice
    for letter in unfound:
        (val,dia) = min_distance_of_letter(letter, found, unfound)
        if val > max_val:
            max_val = val
            best_letter = letter
            best_dia = dia
    return best_letter, best_dia, max_val

def generate_letter_order(found: list, unfound: list) -> (list, list, list):
    """Generates the best letter ordering to solve a substitution cipher

    The lists returned are specially formatted for use in a previously written 
    program. 

    Parameters
    ----------
    found : list
        list of characters that have been found
    unfound : list
        list of characters that have not yet been found

    Returns
    -------
    (list, list, list)
        to_find : the unknown letter that we want to solve for in our substitution
        to_use : the known letter that we will use to solve it
        pos : the position of our known letter in our diagraph
    """

    result_to_find = []
    result_to_use = []
    result_pos = []
    while len(unfound) > 1:
        (letter, dia, val) = best_choice_of_letter(found, unfound)
        # Update found and unfound
        found.append(letter)
        unfound.remove(letter)

        # Format our result for use in cipher breaking program
        result_to_find.append(letter)
        result_pos.append(1- dia.index(letter))
        result_to_use.append(dia[1-dia.index(letter)])

    return result_to_find, result_to_use, result_pos

def main():
    """Very similair fucntionality to generate letter order, but pretty prints output

    This will print our output as
    letter diagraph value
    where value is the rating of how good a choice the letter is
    example:
        h th 2.24010704830432
        r re 0.732929984703371
        s st 0.6535319633072852
        ...
        z
    """

    # Letters assumed to be known and unknown in substitution
    found = ["e","t","a"]
    unfound = ["b","c","d","f","g","h","i","j","k","l","m","n","o","p","q","r","s","u","v","w","x","y","z"]

    # Loop until all letters are known
    while len(unfound) > 1:
        (letter, dia, val) = best_choice_of_letter(found, unfound)
        print(letter, dia, val)
        found.append(letter)
        unfound.remove(letter)
    print(unfound[0])

if __name__ == "__main__":
    main()
