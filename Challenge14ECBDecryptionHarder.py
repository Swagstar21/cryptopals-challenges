"""
Robert Panduru
2018
This is a similar attack to the one from challenge 12. The difference
is that the bytes we can introduce in the plaintext are between a random
number of random bytes and the target bytes. The prefix has to be taken
into account every thing else being the same.
"""

from Crypto.Cipher import AES
from random import randint
import base64

def randomKey():
	key = ""
	for i in range(16):
		key += chr(randint(0, 255))
	return key

nrByte = 0
globalKey = randomKey()

# Generating the prefix
nrOfBytes = randint(0, 30)
prefix = ''
for i in range(nrOfBytes):
	prefix += chr(randint(0, 255))

# Preprends the prefix to the parameter and appends the target string
# and encrypts the result
def encrypt(string):
	global prefix
	cipher = AES.new(globalKey, AES.MODE_ECB)
	string = prefix + string
	string += base64.b64decode("""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK""")
	for i in range(len(string), (len(string) / 16 + 1) * 16):
		string += '\x00'
	return cipher.encrypt(string)

# ECB detection device
def detectionOracle(enc):
	global nrByte
	for i in range(len(enc) / 16 - 1):
		if enc[16 * i : 16 * (i + 1)] == enc[16 * (i + 1) : 16 * (i + 2)]:
			nrByte = i
			return "ECB"
	return "CBC"

# Finding out the block size
lengthOfBytes = -1
for i in range(100):
	ciphertext = encrypt('A' * i)
	if detectionOracle(ciphertext) == 'ECB':
		lengthOfBytes = 16 - (i - (i / 16) * 16)
		lengthOfBytes += 16 * (nrByte - 1)
		break

# Time to figure out the string
keySize = 16
initialString = ''
string = encrypt('')
nrOfBlocks = len(string) / keySize
dim = (lengthOfBytes / 16 + 1) * 16

# Manipulate the input to the oracle to deduce the
# unknown string byte by byte
for k in range(nrOfBlocks + 1):
	for j in range(1, keySize + 1):
		string = encrypt('A' * (keySize - j + dim - lengthOfBytes))
		block = 'A' * (keySize - j + dim - lengthOfBytes) + initialString
		offset = dim / 16
		for i in range(0, 255):
			block += chr(i)
			result = encrypt(block)
			if result[(k + offset) * keySize : (k + offset + 1) * keySize] == string[(k + offset) * keySize : (k + offset + 1) * keySize]:
				initialString += chr(i)
				break
			block = block[:(len(block) - 1)]

print(initialString)