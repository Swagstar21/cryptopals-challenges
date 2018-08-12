"""
Robert Panduru
2018
SHA-1 was a very widespread authentication. It computes a 160-bit variable
given a certain input. Even a small difference between two inputs produces
a massive difference between the resulting digests. This is my implementation
of this hash function.
"""

import binascii
import struct

# We will need to perform bit rotations
def rotateLeft(x, n):
	return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

# XOR between 2 32-bit words
def wordXOR(word1, word2):
	result = [0] * 4
	result[0] = chr(ord(word1[0]) ^ ord(word2[0]))
	result[1] = chr(ord(word1[1]) ^ ord(word2[1]))
	result[2] = chr(ord(word1[2]) ^ ord(word2[2]))
	result[3] = chr(ord(word1[3]) ^ ord(word2[3]))
	return "".join(result)

# It appends to the message a padding and then adds
# the original length of the message
def preprocessing(message):
	ml = len(message) * 8
	message += chr(0x80)
	while len(message) % 64 != 56:
		message += '\x00'
	ml = struct.pack('>Q', ml)
	message += ml
	return message

# Computes the digest of the message while specifying the
# original values of he h's
def computeDigest(message, h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0):
	# Adds the neccesary padding
	processed = preprocessing(message)
	# Breaks the message into 512-bit chunks
	chunks = [processed[i * 64 : (i + 1) * 64] for i in range(len(processed) / 64)]
	# Each chunk is processed individually
	for chunk in chunks:
		# The chunk is broken into 16 32-bit words
		words = [chunk[i * 4 : (i + 1) * 4] for i in range(len(chunk) / 4)]
		# The words are then extended up to 80
		for i in range(16, 80):
			aux = wordXOR(words[i - 3], words[i - 8])
			aux = wordXOR(aux, words[i - 14])
			aux = wordXOR(aux, words[i - 16])
			aux = struct.unpack('>I', aux)[0]
			aux = rotateLeft(aux, 1)
			aux = struct.pack('>I', aux)
			words.append(aux)

		# Time to add to the final result
		a = h0
		b = h1
		c = h2
		d = h3
		e = h4
		# For each word there corresponds a change in h's and thus
		# a change in the final result
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

		# These are 32-bit words and they need to wrap around
		h0 = (h0 + a) & 0xFFFFFFFF
		h1 = (h1 + b) & 0xFFFFFFFF
		h2 = (h2 + c) & 0xFFFFFFFF
		h3 = (h3 + d) & 0xFFFFFFFF
		h4 = (h4 + e) & 0xFFFFFFFF

	# The final result is derived from the registers and it is
	# displayed as a hex string
	digest = format((h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4, 'x')
	digest = "0" * (40 - len(digest)) + digest
	return digest

digest = computeDigest("A" * 20)
print(digest)
