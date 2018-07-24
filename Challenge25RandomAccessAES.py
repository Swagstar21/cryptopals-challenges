"""
Robert Panduru
2018
Encrypting a plaintext with CTR becomes a huge liability
in case there exists a way for the attacker to modify
at will the resulting plaintext even if he doesn't have
acces to the key. Following on this concept, a CTR stream
can be decrypted by parsing the ciphertext and editing every
byte until we find a match.
"""

from Crypto.Cipher import AES
from random import randint
import base64
from Crypto.Util import Counter

# Generating a random key
def randomKey():
	key = ""
	for i in range(16):
		key += chr(randint(0, 255))
	return key

key = randomKey()

# Reading from the file
with open("Challenge25input.txt") as file:
	plaintext = file.readlines()
	length = len(plaintext)

# To find the maximum value of the offset
nrCharacters = 0

for i in range(length):
	for j in range(len(plaintext[i])):
		nrCharacters += 1

# Creates a CTR stream and encrypts the plaintext
def encrypt(plaintext):
	global length
	global key
	ciphertext = []
	ctr = Counter.new(nbits=64,  prefix='\x00\x00\x00\x00\x00\x00\x00\x00', initial_value=0, little_endian=True)
	cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
	for i in range(length):
		ciphertext.append(cipher.encrypt(plaintext[i]))
	return ciphertext

# Creates a counter and decrypts a ciphertext
def decrypt(ciphertext):
	global key
	global length
	plaintext = [""] * len(ciphertext)
	ctr = Counter.new(nbits=64,  prefix='\x00\x00\x00\x00\x00\x00\x00\x00', initial_value=0, little_endian=True)
	cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
	for i in range(length):
		plaintext[i] = cipher.encrypt(ciphertext[i])
	return plaintext

# Will overwrite the byte at position offset with
# newByte and return the new ciphertext
def edit(ciphertext, key, offset, newByte):
	plaintext = decrypt(ciphertext)
	line = -1
	column = -1
	for i in range(len(plaintext)):
		if offset < len(plaintext[i]):
			line = i
			column = offset
			break
		offset = offset - len(plaintext[i])
	plaintext[line] = list(plaintext[line])
	plaintext[line][column] = newByte
	plaintext[line] = ''.join(plaintext[line])
	return encrypt(plaintext)

# Will parse the stream and look for matches by editing
# to reproduce the plaintext
def recover(ciphertext, key, nrCharacters):
	original = ""
	for i in range(nrCharacters):
		for j in range(256):
			aux = edit(ciphertext, key, i, chr(j))
			if aux == ciphertext:
				original += chr(j)
				break
	return original


ciphertext = encrypt(plaintext)
print(recover(ciphertext, key, nrCharacters))

