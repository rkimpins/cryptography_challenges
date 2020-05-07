# What is this?
The idea for this subfolder was to build a substitution cipher solver. The strategy I used was letter and digraph frequency, a well known weakness of substitution ciphers.  

Letter frequencies are taken from https://en.wikipedia.org/wiki/Letter_frequency
Diagraph frequency is taken from http://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/digraphs.html

This was inspired by working through the course "Cryptography I" by Stanford 
University on Coursera. This course can be found at 
https://www.coursera.org/learn/crypto?, and was available on May 7th, 2020.


# Challenges
This method uses statistical frequencies of letters and diagraphs to break a substitution cipher. An obvious flaw of this method is that the smaller our message size, the less likely our assumptions will hold. If we have a message of a couple of lines, we exect the most common letter to be e, but we would not be surprised if it wasn't. It's not hard to imagine messages that contradict this assumption. I used the complete text of Jane Austen's _Pride and Prejudice_ (curtesy of project gutenberg https://www.gutenberg.org/files/1342/1342-h/1342-h.htm). Despite the large size of this message (wc suggests 785,142 characters) our method is not perfect. For this message, our algorithm correctly decrypted 14 out of 26 letters.

Another issue is that many of our diagraph calculations depend on correctly solving previous letters. A single deviation from the expected statistical frequency can have a domino effect and make the rest of our solutions wrong.

Another issue is that if we set hardcoded rules, we may run into words that aren't strictly english, that break these rules. For example, if a character is named Emma, em and ma will occur with much greater frequency then expected. Also, this can break word patterns if we used them.

Finally, there are several other properties of the english language that we could have considered but didn't, which I discuss below.

# Where to go from here
If I had to be honest, I am not perfectly happy with this implementation of breaking substitution ciphers. I imagined building a robust tool that could break single sentence ciphers consistently. Instead, we are only finding half of the letters of a book length message. Here are several things I am considering implementing, or are interesting ideas but too challenging for a fun side project.
	* Include common trigraphs, but only the most common one or two.
	* j,x,q,z are the least common letter by a signifigant margin, so there might be a way to use this information.
	* Use our knowledge of what a valid english word is, like common word patterns, to find letters. This might work better if spaces were included in the message, but it could still work without.
	* Have better diagrah analysis. I am not certain my choice of diagraphs and their order were the most optimal for a robust solver. Manually finding good diagraphs was working better, but it was only tuned to the message I used and it was exhaustive.
	* Instead of depending on a single diagraph to find a letter, combine multiple diagrahs, weight their output by their expected frequency, and output the consensus. This might fix the robustness issue.
	* Instead of solving one letter at a time, combine multiple rules to rule out and limit our options for a letter. For example, keep a list of possible letters, removing ones as we go.
	* Try to limit the chaining of letter solutions. If more letters only depended on (e, t, a) being correct, or we only allow small chians of two or three, our errors wouldn't propogate so much.
	* It might be best just to guess the last letters, and check if the output is a readable message

# Look at this
After completing this, I found an interesting resource that addresses a similair issue. https://inventwithpython.com/cracking/chapter17.html I also found this repository which I haven't had a chance to look through, but seems to contain solutions to multiple ciphers.

