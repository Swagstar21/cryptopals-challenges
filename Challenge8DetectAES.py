"""
Robert Panduru
2018
You can detect when a specific ciphertext is encrypted with AES in
ECB mode by trying to find blocks of the ciphertext that are the same.
This is because ECB is encrypting each block of the plaintext in exactly
the same way with no regard to the other blocks. 2 similar plaintext
blocks will always look the same after encryption.
"""

from Crypto.Cipher import AES
from sys import exit

# Here is the link to the file
# https://cryptopals.com/static/challenge-data/8.txt
with open('input.txt') as file:
	text = file.readlines()
	length = len(text) - 1

# Getting rid of the carriage returns
for i in range(length):
	text[i] = text[i][:(len(text[i]) - 1)]

decryptedText = []

# Decoding the hex strings
for i in range(length):
	decryptedText.append(text[i].decode('hex'))

index = 0

# Will check all the lines for repeating blocks
# The chances that there are repeating blocks in any other
# encryption scheme are practically 0
for line in decryptedText:
	index += 1
	for i in range(len(line) / 16 - 1):
		for j in range(i + 1, len(line) / 16):
			if line[16 * i : 16 * (i + 1)] == line[16 * j : 16 * (j + 1)]:
				print("The line is %d" % (index))
				exit(0)