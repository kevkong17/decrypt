import string
import random
from string import ascii_lowercase

def caesar_encrypt(plain, key):
    cipher = ""
    # makes key, which is single letter, lowercase
    key = key.lower()
    #finds difference between value of letter on ascii value to value of "a" to determine shift value
    change = ord(key) - 97
    #loops through message needed to be encrypted
    for position in range(0, len(plain)):
        #takes every letter in message
        str = plain[position: position + 1]
        #if letter is lowercase, add the difference, loop back through the alphabet if it goes past "z". Add encrypted letter
        if (ord(str) >= 97 and ord(str) <= 122):
            num = ord(str) + change
            if (num > 122):
                num = num - 26
            cipher += chr(num)
        #if letter is uppercase, do the same.
        elif (ord(str) >= 65 and ord(str) <= 90):
            num = ord(str) + change
            if (num > 90):
                num = num - 26
            cipher += chr(num)

        else:

            cipher += str

    return cipher



def caesar_decrypt(cipher, key):
    plain = ""
    #same as encrypt
    key = key.lower()
    change = ord(key) - 97
    #loops through every letter, shifts every letter according to key
    for position in range(0, len(cipher)):
        str = cipher[position: position + 1]
    #if lowercase, shift lowercase
        if (ord(str) >= 97 and ord(str) <= 122):
            num = ord(str) - change
            if (num < 97):
                num = num + 26

            plain += chr(num)

        elif (ord(str) >= 65 and ord(str) <= 90):
            num = ord(str) - change
            if (num > 90):
                num = num + 26

            plain += chr(num)

        else:
            plain += str

    return plain




def vigenere_encrypt(plain, key):
    cipher = ""
    tracker = 0
    for position in range(0, len(plain)):
        # gets letter from message
        str = plain[position: position + 1]  # gets every new letter in cipher
        # if key has space, tracker increases
        if (key[tracker: tracker + 1] == " "):
            tracker += 1
        # letter used to encrypt is letter put into variable
        tempLet = key[tracker: tracker + 1]
        # lowercase that letter
        tempLet = tempLet.lower()
        # find change in shift of that letter
        change = ord(tempLet) - 97  # ascii value of key

        # if letter from message is lowercase, shift forward according to letter
        if (ord(str) >= 97 and ord(str) <= 122):
            num = ord(str) + change
            if (num > 122):
                num -= 26

            cipher += chr(num)
        # if letter from message is uppercase, shift forward according to letter
        elif (ord(str) >= 65 and ord(str) <= 90):
            num = ord(str) + change
            if (num > 90):
                num -= 26
            cipher += chr(num)

        else:
            cipher += str
            continue

        tracker += 1

        if (tracker == len(key)):
            tracker = 0
    return cipher



def vigenere_decrypt(cipher, key):
    plain = ""
    tracker = 0
    for position in range(0, len(cipher)):
        #gets letter from message
        str = cipher[position: position + 1]  # gets every new letter in cipher
        #if key has space, tracker increases
        if (key[tracker: tracker + 1] == " "):
            tracker += 1
        #letter used to encrypt is letter put into variable
        tempLet = key[tracker: tracker + 1]
        #lowercase that letter
        tempLet = tempLet.lower()
        #find change in shift of that letter
        change = ord(tempLet) - 97 #ascii value of key

        #if letter from message is lowercase, shift back according to letter
        if (ord(str) >= 97 and ord(str) <= 122):
            num = ord(str) - change
            if (num < 97):
                num += 26

            plain += chr(num)
        #if letter from message is uppercase, shift back according to letter
        elif (ord(str) >= 65 and ord(str) <= 90):
            num = ord(str) - change
            if (num < 65):
                num += 26
            plain += chr(num)

        else:
            plain += str
            continue


        tracker += 1

        if (tracker == len(key)):
            tracker = 0
    return plain

#good

def monosub_decrypt(cipher, key):
    plain = ""
    #loops through every letter in message and key
    for letter in range(0, len(cipher)):
        found = False
        for position in range(0, len(key)):

            #takes single letter from message
            str = cipher[letter: letter + 1] #take letter in cipher

            #if lowercase, get index where letter in message is equal to letter in key, use the index of key to find out letter in alphabet
            if(ord(str) >= 97 and ord(str) <= 122):
                keylet = key[position: position + 1].lower()
                if(str == keylet):
                    sub = chr(position + 97)
                    plain += sub
                    found = True
                    break


            elif(ord(str) >= 65 and ord(str) <= 90):
                keylet = key[position: position + 1].upper()
                if(str == keylet):
                    sub = chr(position + 65)
                    plain += sub
                    found = True
                    #if found the same letter, just break out to next letter in message
                    break
        if(found == False):
            plain += str

    return plain
	# Assume plain is a string that could contain alphabetic, numeric, and punctuation
	# Upper case letters should map to upper case.  Lower case letters should map to lower case
	# Key is a string of letters 26 long.  Assume each letter only appears once

#good
def monosub_encrypt(plain, key):
    cipher = ""

    for position in range(0, len(plain)):
        #letter in message, turn into lowercase
        str = plain[position].lower()

        #if it is lowercase
        if(ord(str) >= 97 and ord(str) <= 122):
            #if the letter is the same as any of these letters, cipher will add letter in same index in key
            if (str == "a"):
                cipher += key[0:1].lower()

            elif (str == "b"):
                cipher += key[1:2].lower()

            elif (str == "c"):
                cipher += key[2:3].lower()

            elif (str == "d"):
                cipher += key[3:4].lower()

            elif (str == "e"):
                cipher += key[4:5].lower()

            elif (str == "f"):
                cipher += key[5:6].lower()

            elif (str == "g"):
                cipher += key[6:7].lower()

            elif (str == "h"):
                cipher += key[7:8].lower()

            elif (str == "i"):
                cipher += key[8:9].lower()

            elif (str == "j"):
                cipher += key[9:10].lower()

            elif (str == "k"):
                cipher += key[10:11].lower()

            elif (str == "l"):
                cipher += key[11:12].lower()

            elif (str == "m"):
                cipher += key[12:13].lower()

            elif (str == "n"):
                cipher += key[13:14].lower()

            elif (str == "o"):
                cipher += key[14:15].lower()

            elif (str == "p"):
                cipher += key[15:16].lower()

            elif (str == "q"):
                cipher += key[16:17].lower()

            elif (str == "r"):
                cipher += key[17:18].lower()

            elif (str == "s"):
                cipher += key[18:19].lower()

            elif (str == "t"):
                cipher += key[19:20].lower()

            elif (str == "u"):
                cipher += key[20:21].lower()

            elif (str == "v"):
                cipher += key[21:22].lower()

            elif (str == "w"):
                cipher += key[22:23].lower()

            elif (str == "x"):
                cipher += key[23:24].lower()

            elif (str == "y"):
                cipher += key[24:25].lower()

            elif (str == "z"):
                cipher += key[25:26].lower()

        elif(ord(str) >= 65 and ord(str) <= 90):
            if (str == "A"):
                cipher += key[0:1]

            elif (str == "B"):
                cipher += key[1:2]

            elif (str == "C"):
                cipher += key[2:3]

            elif (str == "D"):
                cipher += key[3:4]

            elif (str == "E"):
                cipher += key[4:5]

            elif (str == "F"):
                cipher += key[5:6]

            elif (str == "G"):
                cipher += key[6:7]

            elif (str == "H"):
                cipher += key[7:8]

            elif (str == "I"):
                cipher += key[8:9]

            elif (str == "J"):
                cipher += key[9:10]

            elif (str == "K"):
                cipher += key[10:11]

            elif (str == "L"):
                cipher += key[11:12]

            elif (str == "M"):
                cipher += key[12:13]

            elif (str == "N"):
                cipher += key[13:14]

            elif (str == "O"):
                cipher += key[14:15]

            elif (str == "P"):
                cipher += key[15:16]

            elif (str == "Q"):
                cipher += key[16:17]

            elif (str == "R"):
                cipher += key[17:18]

            elif (str == "S"):
                cipher += key[18:19]

            elif (str == "T"):
                cipher += key[19:20]

            elif (str == "U"):
                cipher += key[20:21]

            elif (str == "V"):
                cipher += key[21:22]

            elif (str == "W"):
                cipher += key[22:23]

            elif (str == "X"):
                cipher += key[23:24]

            elif (str == "Y"):
                cipher += key[24:25]
            elif (str == "Z"):
                cipher += key[25:26]
        else:
            cipher += str



	# Assume plain is a string that could contain alphabetic, numeric, and punctuation
	# Upper case letters should map to upper case.  Lower case letters should map to lower case
	# Key is a string of letters 26 long.  Assume each letter only appears once
    return cipher


#good
def key_gen():
    key = ''

    #counter = 25
    list = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
            'v', 'w', 'x', 'y', 'z']
    # loops through 0 and 26
    random.shuffle(list)

    for a in range(len(list)):
        key += list[a]



	# Key is a string of letters 26 long.
	# Some functions that may help
	# random.sample
	# string.ascii_uppercase
	# ''.join()

    return key

#
def chi_squared_test(text):
    score = 0


    letfreq = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    letters = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v",
           "w", "x", "y", "z"]
    frequency = [0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025,
             0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150,
             0.01974, 0.00074]

    #goes through every letter in text and counts frequency
    counter = 0
    for num in range(len(text)):
        for letter in range(len(letters)):
            str = (text[num:num+1].lower())
            if (str == letters[letter]):
                letfreq[letter] += 1
                counter += 1

    #uses summation formula to compare frequency of english language with frequency of text
    for let in range(len(letfreq)):
        ca = letfreq[let]
        #multiplies decimal of english letter frequency to total amount of letters
        ei = frequency[let] * counter
        num = (ca - ei) * (ca - ei)
        num = num / ei
        score += num
    # Sum from i = A to Z of (C_i - E_i)^2/E_i.  Where C_A is the count (not probability) of A and E_A is the expected count of A
    # Expected distribution is [0.08167,0.01492,0.02782,0.04253,0.12702,0.02228,0.02015,0.06094,0.06966,0.00153,0.00772,0.04025,0.02406,0.06749,0.07507,0.01929,0.00095,0.05987,0.06327,0.09056,0.02758,0.00978,0.02360,0.00150,0.01974,0.00074];
    # Expected count is tot_letters * distribution
    return score

def expected_key(text):
	key = -1 # Sets the current best key to -1
	score = 100000 # Sets the current score to a really high score
	current = 0
	letters = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u",
			   "v", "w", "x", "y", "z"]
    #loops through all the letters in list and encrypts text according to letter
	for a in range(len(letters)):
        #sets encrypted equal to message shifted
		encrypted = caesar_encrypt(text, letters[a])
        #tests encrypted message, returns the lowest scored key
		current = chi_squared_test(encrypted)
		if (current < score):
			score = current
			key = chr(a + 97)



	return key, score

# print expected_key(lang)

def decrypt_802():
    output_file = open('caesar_decrypted_KongZhou.txt', 'w')  # Replace YOUR_GROUP_NAME with a name for your group
    
    for i in range(1, 803):
        filename = "CAESAR" + str(i) + ".txt"

    # in here put your code to get the text out of the file and put it in a string

        texts = open(filename,'r').read()
        key, score = expected_key(texts)  # Find the key for the string.  Replace "" with your string
        plain = caesar_encrypt(texts, key)  # replace "" with your string
        output_file.write(key + "," + str(score) + "," + plain + 'w')  # For CAESAR1.txt this should write 9, 20.55, IN ANOTHER MOMENT DOWN WENT ALICE AFTER IT  NEVER ONCE CONSIDERING HOW IN THE WORLD SHE WAS TO GET OUT AGAIN


    output_file.close()


def main():
    print caesar_encrypt("This is our first input", "E")
    print caesar_decrypt("Xlmw mw syv jmvwx mrtyx", "E")
    print vigenere_encrypt("WILL THIS ENCRYPTION WORK?", "crypto")
    print vigenere_decrypt("YZJA MVKJ CCVFAGRXHB YFPZ?", "crypto")
    decrypt_802()
    caesartexts = open("caesar_test.txt", 'r').read()
    print caesartexts
    for a in ascii_lowercase:
        print caesar_encrypt(caesartexts, a)
    vigeneretexts = open("vigenere_test.txt", 'r').read()
    print vigeneretexts
    print vigenere_decrypt(vigeneretexts, "TURING")

    monotest = open("mono_test.txt", 'r').read()
    print monotest
    print monosub_decrypt(monotest, "ISYVKJRUXEDZQMCTPLOFNBWGAH")

	#Put your cases here
	#Including the following
	# Test your Caesar encryption, print the input and output to screen
	# Test your Caesar decryption, print the input and input to screen
	# Test your Vigenere encryption, print the input and output to screen
	# Test your Vigenere decryption, print the input and input to screen
	# Test your mono encryption, print the input and output to screen
	# Test your mono decryption, print the input and input to screen
	# run decrypt_802()

main()


