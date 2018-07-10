"""
Robert Panduru
2018
The following program will encrypt a sequence of characters,
prepended and appended by a number of random bytes, in ECB mode 
or in CBC mode. The mode is chosen randomly. The detection oracle
will look for similar blocks and if some are found it means that
the plaintext was encrypted using ECB.
"""

from Crypto.Cipher import AES
from random import randint

# In order to generate a random key and IV's
def randomKey():
	key = ""
	for i in range(16):
		key += chr(randint(0, 255))
	return key

# Will encrypt a specific string in CBC or ECB
def randomEncryption(string):
	length = len(string)
	choice = randint(0, 1)
	str1 = ""
	str2 = ""
	for i in range(randint(5, 11)):
		str1 += chr(randint(0,255))

	for i in range(randint(5, 11)):
		str2 += chr(randint(0,255))

	string = str1 + string + str2
	key = randomKey()

	if choice == 0:
		mode = "ECB"
		decipher = AES.new(key, AES.MODE_ECB)
	elif choice == 1:
		mode = "CBC"
		IV = randomKey()
		decipher = AES.new(key, AES.MODE_CBC, IV)

	# Will append \x00's to give it a good length in order
	# to encrypt it
	for i in range(len(string), (len(string) / 16 + 1) * 16):
		string += chr(0)

	print(mode)
	string = decipher.encrypt(string)
	return string

# Will exploit ECB's vulnerability described in challenge 8
def detectionOracle(enc):
	for i in range(len(enc) / 16 - 1):
		if enc[16 * i : 16 * (i + 1)] == enc[16 * (i + 1) : 16 * (i + 2)]:
			return "ECB"
	return "CBC"

# I chose a string of size 16 and copied it a few
# times to make it easier to spot the mode of
# encryption
cipher = randomEncryption("YELLOW SUBMARINE" * 4)
print(detectionOracle(cipher))
