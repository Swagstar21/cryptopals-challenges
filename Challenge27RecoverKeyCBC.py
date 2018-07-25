"""
Robert Panduru
2018
Systems that use CBC mode often present 2 flaws that are fatal
together. One is using the key as the IV and the second one is
throwing errors when the plaintext obtained by decrypting contains
nonprintable characters, thus exposing the plaintext via the error.
By tampering the ciphertext, the key can be deduced by XOR'ing the
injected plaintext with the bytes of the plaintext that are obtained
and are "out-of-bounds". The ciphertext is tampered by setting all
the bits from the second block to 0 so the third block is not
dependant on anything but itself. The first block is XOR'ed against
the IV but we know that the first and third block were the same before
encryption. By finding the IV we find the key.
"""

from Crypto.Cipher import AES
from random import randint

# Key and IV generator
def randomKey():
	key = ""
	for i in range(16):
		key += chr(randint(0, 255))
	return key

globalKey = randomKey()
IV = globalKey
cipher = AES.new(globalKey, AES.MODE_CBC, IV)

# Encryption function
def encrypt(string):
	global cipher
	global IV
	return IV + cipher.encrypt(string)

# Returns the recovered plaintext if it contains
# nonprintable characters or 1 if it is legitimate
def decrypt(string):
	global cipher
	string = cipher.decrypt(string)
	string = string[16:]
	for ch in string:
		if ord(ch) < 30 or ord(ch) > 126:
			return string
	return 1

# Create 3 blocks of text and then tamper the ciphertext
plaintext = 'A' * 48
ciphertext = encrypt(plaintext)
ciphertext = list(ciphertext)
# The second block is set to all 0's
# and the third one is identical to the first
ciphertext[32 : 48] = [chr(0)] * 16
ciphertext[48:] = ciphertext[16 : 32]
ciphertext = "".join(ciphertext)
plaintext = decrypt(ciphertext)
# If the plaintext is gibberish we can find the IV
# which is also the key
if plaintext != 1:
	key = ''
	for i in range(16):
		key += chr(ord(plaintext[32 + i]) ^ ord('A'))

print("The key is:\n%s" % (globalKey))
print("The found key is:\n%s" % (key))
print("Are they the same?\n%s" % (key == globalKey))