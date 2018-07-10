"""
Robert Panduru
2018
We try to find out the contents of an unknown string that is base64'd
so we can't read it. It is then encrypted with a random key. First things
first, we try to find the size of the block. This is done by prepending
an increasing number of A's to an empty string. When 2 blocks will have
been encrypted the oracle will return 'ECB', meaning the block size is
half the number of A's appended. After deducing the block size we will
try to find the unknown string. We encrypt block size - 1 'A' and the
unknown string and observe the ciphertext. We will try to match the first
block of ciphertext with the one obtained by encrypting the same number
of A's and another character. We will try all the 256 possibilities for
this character. We use the same tehnique for all the bytes of the
string we try to recover.
"""

from Crypto.Cipher import AES
from random import randint
import base64

# Key generator
def randomKey():
	key = ""
	for i in range(16):
		key += chr(randint(0, 255))
	return key

globalKey = randomKey()

# ECB encryption function
def encrypt(string):
	cipher = AES.new(globalKey, AES.MODE_ECB)
	string += base64.b64decode("""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK""")
	for i in range(len(string), (len(string) / 16 + 1) * 16):
		string += '\x00'
	return cipher.encrypt(string)

# The oracle from earlier
def detectionOracle(enc):
	for i in range(len(enc) / 16 - 1):
		if enc[16 * i : 16 * (i + 1)] == enc[16 * (i + 1) : 16 * (i + 2)]:
			return "ECB"
	return "CBC"

# By encrypting a certain number of A's we can deduce
# the block size. The first value that causes the oracle
# to return "ECB" is the size of the block
string = ''
for i in range(1, 100):
	string += 'A'
	ciphertext = encrypt(string)
	mode = detectionOracle(ciphertext)
	if mode == "ECB":
		blockSize = i / 2
		break

initialString = ''
string = encrypt('')
nrOfBlocks = len(string) / blockSize

# We will manipulate the number of A's at the beginning of the string
# to find out the bytes of the unknown string. The first byte can be
# found by creating of block of (blockSize - 1) A's and then appending 
# different characters. After that we can try all the possible characters 
# and encrypt the block each time and try to see if the blocks match.
# We use an initial ciphertext which contains only the A's and the string
# and another one with the A's and the character we try to match
for k in range(nrOfBlocks):
	for j in range(1, blockSize + 1):
		string = encrypt('A' * (blockSize - j))
		block = 'A' * (blockSize - j) + initialString
		for i in range(0, 255):
			block += chr(i)
			result = encrypt(block)
			if result[k * blockSize : (k + 1) * blockSize] == string[k * blockSize : (k + 1) * blockSize]:
				initialString += chr(i)
				break
			block = block[:(len(block) - 1)]
	

print(initialString)