"""
Robert Panduru
2018
A vulnerability of SHA-1 can be exploited by using a so-called
length extension. By using a previously computed hash a message
can be counterfeited. The original message is used as a starting
point for getting a new hash that authenticates our counterfeit
message.
"""

import binascii
import struct
import hashlib
from random import randint

# Function which generates a secret prefix for the MAC
def randomKey():
	key = ''
	for i in range(randint(2, 19)):
	# for i in range(0):
		key += chr(randint(0, 255))
	return key

# Left rotation for a 32-bit word
def rotateLeft(x, n):
	return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

# XOR between 2 32-bit words represented as strings
def wordXOR(word1, word2):
	result = [0] * 4
	result[0] = chr(ord(word1[0]) ^ ord(word2[0]))
	result[1] = chr(ord(word1[1]) ^ ord(word2[1]))
	result[2] = chr(ord(word1[2]) ^ ord(word2[2]))
	result[3] = chr(ord(word1[3]) ^ ord(word2[3]))
	return "".join(result)

# Computes the glue padding for a message but allows the
# user to take into account previous contents using the
# ml variable
def gluePadding(message, ml):
	padding = ''
	padding += chr(0x80)
	while (ml + len(padding)) % 64 != 56:
		padding += '\x00'
	ml = 8 * ml
	ml = struct.pack('>Q', ml)
	padding += ml
	return padding

# The same function from the last challenge
def preprocessing(message):
	ml = len(message) * 8
	message += chr(0x80)
	while len(message) % 64 != 56:
		message += '\x00'
	ml = struct.pack('>Q', ml)
	message += ml
	return message

# Deduces the values of the h's from a
# given digest
def calculateRegisters(digest):
	h4 = digest & 0xFFFFFFFF
	digest = digest >> 32
	h3 = digest & 0xFFFFFFFF
	digest = digest >> 32
	h2 = digest & 0xFFFFFFFF
	digest = digest >> 32
	h1 = digest & 0xFFFFFFFF
	digest = digest >> 32
	h0 = digest & 0xFFFFFFFF
	digest = digest >> 32

	return h0, h1, h2, h3, h4

# Computes the digest of a message with a
# set of registers. The result is an integer
def computeDigest(message, h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0):
	processed = message
	chunks = [processed[i * 64 : (i + 1) * 64] for i in range(len(processed) / 64)]
	for chunk in chunks:
		words = [chunk[i * 4 : (i + 1) * 4] for i in range(len(chunk) / 4)]
		for i in range(16, 80):
			aux = wordXOR(words[i - 3], words[i - 8])
			aux = wordXOR(aux, words[i - 14])
			aux = wordXOR(aux, words[i - 16])
			aux = struct.unpack('>I', aux)[0]
			aux = rotateLeft(aux, 1)
			aux = struct.pack('>I', aux)
			words.append(aux)
		a = h0
		b = h1
		c = h2
		d = h3
		e = h4
		for i in range(80):
			if 0 <= i <= 19:
				f = d ^ (b & (c ^ d))
				k = 0x5A827999
			elif 20 <= i <= 39:
				f = b ^ c ^ d
				k = 0x6ED9EBA1
			elif 40 <= i <= 59:
				f = (b & c) | (b & d) | (c & d)
				k = 0x8F1BBCDC
			elif 60 <= i <= 79:
				f = b ^ c ^ d
				k = 0xCA62C1D6
			temp = (rotateLeft(a, 5) + f + e + k + struct.unpack('>I', words[i])[0]) & 0xFFFFFFFF
			e = d
			d = c
			c = rotateLeft(b, 30)
			b = a
			a = temp

		h0 = (h0 + a) & 0xFFFFFFFF
		h1 = (h1 + b) & 0xFFFFFFFF
		h2 = (h2 + c) & 0xFFFFFFFF
		h3 = (h3 + d) & 0xFFFFFFFF
		h4 = (h4 + e) & 0xFFFFFFFF

	digest = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4

	return digest

# Prints the digest in a pretty form
def hexDigest(message, h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0):
	digest = computeDigest(message, h0, h1, h2, h3, h4)
	digest = format(digest, 'x')
	digest = "0" * (40 - len(digest)) + digest
	return digest

# The secret prefix used in the MAC
key = randomKey()
found = 0
# The message we first used to get a first digest
originalMessage = "Yellow submarine" * 10
# We want to obtain a digest obtained from a message
# that contains both the secret prefix and the following
# string
newMessage = ";admin=true;"

# We are trying to find out the length of the secret prefix
# by iterating though some possible lengths and then we will
# try to match the digests. I kept the possibilities number low
# because a lot of collisions happen.
for j in range(20):
	if found == 1:
		break
	# We obtain the digest of the current configuration
	message = key + originalMessage
	message += gluePadding(message, len(originalMessage) + j)
	digest = computeDigest(message)

	# We fix the registers used
	h0, h1, h2, h3, h4 = calculateRegisters(digest)

	# This digest is here to illustrate the correct answer. I used here some
	# resources of the system that wouldn't be available in this scenario ie
	# the length of the secret prefix
	padding = gluePadding(message + newMessage, len(message) + len(newMessage))
	digest = hexDigest(message + newMessage + padding)

	# We are trying some sizes for the original message and look out
	# for digest matches
	for i in range(10):
		padding = gluePadding(newMessage, len(newMessage) + 64 * i)
		newDigest = hexDigest(newMessage + padding, h0, h1, h2, h3, h4)
		if newDigest == digest:
			found = 1
			print("The digest we obtained though length extension:")
			print(newDigest)
			print("The digest we obtained for reference")
			print(digest)
			break