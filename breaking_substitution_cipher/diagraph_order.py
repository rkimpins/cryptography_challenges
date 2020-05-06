# Setup global vaiables that hold diagraph frequency information
import json
json_data = open('diagraph_frequency.txt')
global_diagraph_freq = json.load(json_data)

global_diagraph_freq_list = sorted(global_diagraph_freq.items(), key=lambda kv: kv[1])
global_diagraph_freq_list.reverse()

global_total_diagraphs = sum(global_diagraph_freq.values())


def distance_to_next_match(diagraph, letter, pos, unfound):
    if diagraph == None:
        return float("-inf"), ""
    min_val = float("inf")
    min_dia = ""
    dias = {}
    for c in unfound:
        if c == diagraph[1-pos] or c == letter:
            continue
        if pos:
            val = c+letter
        else:
            val = letter+c
        #dias[val] = d[val]

        diff= global_diagraph_freq[diagraph] - global_diagraph_freq[val]
        if min_val > diff:
            min_val = diff
            min_dia = val

    return min_val/global_total_diagraphs * 100, min_dia


def min_distance_of_letter(letter, found, unfound):
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
    #print(diagraph0, diagraph1)
    (z0,z0d) = distance_to_next_match(diagraph0, letter, 0, unfound)
    (z1,z1d) = distance_to_next_match(diagraph1, letter, 1, unfound)
    #print(z0d, z1d)
    if z0 > z1:
        return z0, diagraph0
    else:
        return z1, diagraph1

def best_choice_of_letter(found, unfound):
    best_letter = ""
    max_val = float("-inf")
    best_dia = ""
    for letter in unfound:
        (val,dia) = min_distance_of_letter(letter, found, unfound)
        #print(letter, val)
        if val > max_val:
            max_val = val
            best_letter = letter
            best_dia = dia
    return best_letter, best_dia, max_val

def generate_letter_order(found, unfound):
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
    #http://practicalcryptography.com/media/cryptanalysis/files/english_bigrams_1.txt
    found = ["e","t","a"]
    unfound = ["b","c","d","f","g","h","i","j","k","l","m","n","o","p","q","r","s","u","v","w","x","y","z"]

    result_to_find = []
    result_to_use = []
    result_pos = []
    while len(unfound) > 1:
        (letter, dia, val) = best_choice_of_letter(found, unfound)

        print(letter, dia, val)
        found.append(letter)
        unfound.remove(letter)
    print(unfound[0])

if __name__ == "__main__":
    main()
