"""
Panduru Robert
2018
This is the classical padding attack on the CBC mode of AES.
It abuses information that indirectly leaks the last bytes
of the tampered plaintext. As the previous attacks, the goal
is to exploit CBC's error propagation vulnerability, this time
trying to obtain specific padding bytes to find out their
intermediate states and then original values.
"""

from Crypto.Cipher import AES
from random import randint
import base64

# For the key and IV
def randomKey():
	key = ""
	for i in range(16):
		key += chr(randint(0, 255))
	return key

# Checks the padding
def paddingValidation(string):
	byte = string[len(string) - 1]
	if byte == '\x00':
		return False
	value = ord(byte)
	for i in range(len(string) - 1, len(string) - 1 - value, -1):
		if string[i] != byte:
			return False
	return True

globalKey = randomKey()
IV = randomKey()
cipher = AES.new(globalKey, AES.MODE_CBC, IV)

# Chooses a string at random, appends the padding and then encrypts it
def encrypt():
	global cipher
	global IV
	strings = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=", 
	"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
	"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]
	string = strings[randint(0, len(strings) - 1)]
	string = base64.b64decode(string)
	print(string)
	length = len(string)
	lengthAppended = (length / 16 + 1) * 16
	for i in range(length, lengthAppended):
		string += chr(lengthAppended - length)
	return IV + cipher.encrypt(string)

# Decrypts the ciphertext
def decrypt(string):
	global cipher
	string = cipher.decrypt(string)
	return string

# Checks the padding of the plaintext
def decryptAndValidate(string):
	return paddingValidation(decrypt(string))

# Initializations
ciphertext = encrypt()
initialString = ''
old = ciphertext

# We will work only on the last 2 cipher blocks and then cut
# the last one after decrypting it to keep it simple
for block in range(len(ciphertext) / 16):
	ciphertext = old
	intermediateState = ''
	for j in range(16):
		ciphertext = list(ciphertext)
		# We transform all the previous values in order to obtain the
		# desired padding
		for k in range(j):
			ciphertext[len(ciphertext) - 1 - 16 - k] = chr(ord(intermediateState[k]) ^ (j + 1))
		ciphertext = "".join(ciphertext)
		# We don't want to XOR a value with itself because this will throw off
		# the previous computations ie. x ^ x = 0 for any x
		aux = ciphertext[len(ciphertext) - 1 - 16 - j]
		found = 0
		# Checking all possibilities
		for i in range(0, 256):
			ciphertext = list(ciphertext)
			ciphertext[len(ciphertext) - 1 - 16 - j] = chr(i)
			ciphertext = "".join(ciphertext)
			if decryptAndValidate(ciphertext) == True:
				if aux != chr(i):
					intermediateState += chr(i ^ (j + 1))
					initialString += chr(i ^ (j + 1) ^ ord(aux))
					found = 1
					break
		# If XOR'ing with itself is the only possibility we will do it
		if found == 0:
			intermediateState += chr(ord(aux) ^ (j + 1))
			initialString += chr(ord(aux) ^ (j + 1) ^ ord(aux))
	# Cut the last block
	old = old[:len(old) - 16]

# The plaintext is reversed
reverse = initialString[::-1]

# Eliminate all the gibberish
index = len(reverse) - 1
while ord(reverse[index]) < 32 or ord(reverse[index]) > 132:
	index -= 1
reverse = reverse[:index + 1]

# Get rid of the IV
print(reverse[16:])
