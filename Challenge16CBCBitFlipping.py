"""
Robert Panduru
2018
This program is another attack on cookies with shoddy
security. The goal is to obtain a ciphertext that
once decrypted it will give admin privileges to the
attacker. This is done by modifying bytes of the ciphertext
and observing how the bytes in the next block change after
decryption. CBC has this property because its scheme implies
XOR'ing each block with the previous one. This means that
altering a byte in the block propagates in the next one.
Thus, the plaintext can be altered at will.
"""

from Crypto.Cipher import AES
from random import randint

def randomKey():
	key = ""
	for i in range(16):
		key += chr(randint(0, 255))
	return key

globalKey = randomKey()
IV = randomKey()
cipher = AES.new(globalKey, AES.MODE_CBC, IV)
len1 = -1
len2 = -1

# Some random cookie elements are added to the input string and then
# encrypted
def encrypt(string):
	global cipher
	global IV
	global len1
	global len2
	string = string.replace(';', "';'")
	string = string.replace('=', "'='")
	prefix = "comment1=cooking%20MCs;userdata="
	len1 = len(prefix)
	postfix = ";comment2=%20like%20a%20pound%20of%20bacon"
	len2 = len(postfix)
	string = prefix + string + postfix
	for i in range(len(string), (len(string) / 16 + 1) * 16):
		string += chr(0)
	return IV + cipher.encrypt(string)

# This function returns True is the contents of the input
# contain ";admin=true;" after decryption
def decrypt(string):
	global cipher
	string = cipher.decrypt(string)
	print(string)
	index = string.find(";admin=true;")
	if index == -1:
		return False
	return True

# We need a random ciphertext which we can tamper with
ciphertext = encrypt("A" * 32)
ciphertext = list(ciphertext)
needed = ";admin=true;AAAA"

# We need the bits that differ between 'A' and every other
# character that is needed and then we propagate that change
# through the blocks
for i in range(len1, len1 + len(needed)):
	ciphertext[i] = chr(ord(ciphertext[i]) ^ ord(needed[i % 16]) ^ ord('A'))


ciphertext = "".join(ciphertext)
found = decrypt(ciphertext)
print(found)
