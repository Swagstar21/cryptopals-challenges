"""
Robert Panduru
2018
Breaking CTR that uses the same counter for all messages is similar
to breaking a Viginere cipher so I used transposition and character
frequency to deduce the plaintexts.
"""

from Crypto.Cipher import AES
from random import randint
import base64
from Crypto.Util import Counter

def randomKey():
	key = ""
	for i in range(16):
		key += chr(randint(0, 255))
	return key

key = randomKey()

# File for challenge 19:
# https://cryptopals.com/sets/3/challenges/19
# File for challenge 20:
# https://cryptopals.com/static/challenge-data/20.txt
with open("input.txt") as file:
	plaintext = file.readlines()
	length = len(plaintext) - 1

ciphertext = []
maximLength = 0

# Encrypting the lines using the same counter each time
for i in range(length):
	ctr = Counter.new(nbits=64,  prefix='\x00\x00\x00\x00\x00\x00\x00\x00', initial_value=0, little_endian=True)
	cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
	plaintext[i] = plaintext[i][:len(plaintext[i])]
	plaintext[i] = base64.b64decode(plaintext[i])
	ciphertext.append(cipher.encrypt(plaintext[i]))
	if len(plaintext[i]) > maximLength:
		maximLength = len(plaintext[i])

# We will use a similar approach as in the repeating XOR key
# aka the Vigenere cipher
transposed = [''] * maximLength
key = []
for i in range(len(ciphertext)):
	for j in range(len(ciphertext[i])):
		transposed[j] += ciphertext[i][j]

# Looking for the suitable permutations by exploring all the possibilities
# and choosing the one which has the smallest score according to the
# character frequencies
for i in range(len(transposed) - 1):
	minim = 99999999999999999.9
	for k in range(256):
		# Initializing
		nrE = 0
		nrA = 0
		nrT = 0
		nrSpace = 0
		nrTotal = 0
		nrO = 0
		nrI = 0
		nrN = 0
		nrOthers = 0
		# Checking to see if the decrypted characters match
		# an English text
		for j in range(len(transposed[i])):
			aux = ord(transposed[i][j]) ^ k
			if aux < 31 or aux > 122:
				break
			nrTotal += 1
			if aux == ord('E') or aux == ord('e'):
				nrE += 1
			elif aux == ord('A') or aux == ord('a'):
				nrA += 1
			elif aux == ord('T') or aux == ord('t'):
				nrT += 1
			elif aux == ord('O') or aux == ord('o'):
				nrO += 1
			elif aux == ord('I') or aux == ord('i'):
				nrI += 1
			elif aux == ord('N') or aux == ord('n'):
				nrN += 1
			elif aux == ord("`") or aux == ord("@") or aux == ord("*") \
			or aux == ord("+") or aux == ord("^") or aux == ord("=") or\
			aux == ord("&") or aux == ord("#") or (aux > ord('0') and aux < ord('9')) \
			or aux == ord("\\") or aux == ord("/") or aux == ord("[") or aux == ord("]")\
			or aux == ord("@") or aux == ord("{") or aux == ord("'") or aux == ord("}"):
				nrOthers += 1
			elif aux == ord(' '):
				nrSpace += 1
			# The higher the score the higher the chance that we didn't
			# find the correct plaintext
			score = (12 - 100.0 * nrE / nrTotal) ** 2 + (8 - 100.0 * nrA / nrTotal) ** 2 + \
			(9 - 100.0 * nrT / nrTotal) ** 2 + (15 - 100.0 * nrSpace / nrTotal) ** 2 +\
			(7 - 100.0 * nrO / nrTotal) ** 2 + (7 - 100.0 * nrI / nrTotal) ** 2 +\
			(7 - 100.0 * nrN / nrTotal) ** 2 + 1 * nrOthers ** 4
			if score < minim:
				minim = score
				char = k
	key.append(char)


result = [""] * len(ciphertext)

# Manual permutations for bytes of the key which
# were wrong

# For challenge 19
# key[0] = ord(ciphertext[0][0]) ^ ord('I')
# key[30] = ord(ciphertext[0][30]) ^ ord('y')
# key[31] = ord(ciphertext[4][31]) ^ ord(' ')
# key[32] = ord(ciphertext[4][32]) ^ ord('h')
# key[33] = ord(ciphertext[4][33]) ^ ord('e')
# key[34] = ord(ciphertext[4][34]) ^ ord('a')
# key[35] = ord(ciphertext[4][35]) ^ ord('d')
# key[36] = ord(ciphertext[len(ciphertext) - 2][36]) ^ ord('n')
# key[37] = ord(ciphertext[len(ciphertext) - 2][37]) ^ ord(' ')

# For challenge 20
key[0] = ord(ciphertext[0][0]) ^ ord('I')
key[90] = ord(ciphertext[11][90]) ^ ord('r')
key[95] = ord(ciphertext[2][95]) ^ ord('k')
key[96] = ord(ciphertext[41][96]) ^ ord('i')
key[97] = ord(ciphertext[41][97]) ^ ord('n')
key[98] = ord(ciphertext[41][98]) ^ ord(' ')
key[99] = ord(ciphertext[41][99]) ^ ord('f')
key[100] = ord(ciphertext[41][100]) ^ ord('u')
key[101] = ord(ciphertext[41][101]) ^ ord('l')
key[102] = ord(ciphertext[41][102]) ^ ord('l')
key[103] = ord(ciphertext[26][103]) ^ ord('e')
key[104] = ord(ciphertext[26][104]) ^ ord(' ')
key[105] = ord(ciphertext[26][105]) ^ ord('w')
key[106] = ord(ciphertext[26][106]) ^ ord('h')
key[107] = ord(ciphertext[26][107]) ^ ord('o')
key[108] = ord(ciphertext[26][108]) ^ ord('l')
key[109] = ord(ciphertext[26][109]) ^ ord('e')
key[110] = ord(ciphertext[26][110]) ^ ord(' ')
key[111] = ord(ciphertext[26][111]) ^ ord('s')
key[112] = ord(ciphertext[26][112]) ^ ord('c')
key[113] = ord(ciphertext[26][113]) ^ ord('e')
key[114] = ord(ciphertext[26][114]) ^ ord('n')
key[115] = ord(ciphertext[26][115]) ^ ord('e')
key[116] = ord(ciphertext[26][116]) ^ ord('r')

# Decrypting with the obtained key
for i in range(len(ciphertext)):
	for j in range(min(len(ciphertext[i]), len(key))):
		result[i] += chr(ord(ciphertext[i][j]) ^ key[j])

# Printing the lyrics
for i in range(len(result)):
	print(result[i])