# What is this?
The idea for this subfolder was to build a N Time Pad solver. The strategy I used was crib dragging

Common english words are taken from https://en.wikipedia.org/wiki/Most_common_words_in_English

This was inspired by working through the course "Cryptography I" by Stanford 
University on Coursera. This course can be found at 
https://www.coursera.org/learn/crypto?, and was available on May 14th, 2020.

# Usage
Run python3 breaking_two_time_pad.py to start the interactive solver. Currently, the only way to select different ciphers from those provided is to edit the contents of ciphers.txt. Happy cracking.

# Challenges
The first issue I ran into was issues with string encoding. I originally tried to encode and decode everything as ascii, but quickly realized this would break the program when non-ascii characters were encountered. Once I converted to ISO-8859-1 encoding, everything worked out

The second big issue I ran into was how to select the correct result after crib dragging. The length of ciphers I was using meant that printing all results and just letting the user choose was not practical. I decided to write some functions that determine if a result could be some combination of english words, which I am very proud of.

# Where to go from here
The code I wrote for filtering the results of crib dragging could use more refining. Also, because I used regex, the code doesn't pla nice with certain punctuation characters, like periods (.) and question marks (?). I would like to eventually include searching for those.

# Look at this
After completing this, I found an interesting repository that attempts much the same thing. They don't filter the crib drag results, but it seems like a solid implementation of this idea. https://github.com/SpiderLabs/cribdrag

# What I learned
Where is what I learned
	* I implemented some basic tests using pytest, which could definitely be improved on. This was my first time using it.
	* I had never heard of Crib Dragging before this.
	* I got some experience handling strings in python, especially when they are not simple ascii.
	* I used regular expressions, which I had heard of but never used in a project.
	* I used the itertools library, but the code ultimately ended up being removed.
