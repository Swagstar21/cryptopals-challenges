"""
Robert Panduru
2018
This program emulates an attack on a cookie encrypted with AES
in ECB mode. The goal is to create an account that has admin
privileges by manipulating the ciphertext sent to the web server.
"""

from Crypto.Cipher import AES
from random import randint

# Random ID
lastID = 10

# Key generator
def randomKey():
	key = ""
	for i in range(16):
		key += chr(randint(0, 255))
	return key

globalKey = randomKey()
cipher = AES.new(globalKey, AES.MODE_ECB)

# Function that generates an entry for a new user
def profile_for(string):
	global lastID
	profile = {}
	profile['email'] = string[:len(string)].translate(None, '&=')
	profile['ID'] = str(lastID)
	profile['role'] = 'user'
	return profile

# Generates a profile from an email address and then creates
# a cookie from it
def encode(string):
	profile = profile_for(string)
	result = ''
	result += 'email=' + profile['email'] + '&uid=' + profile['ID'] + '&role=' + profile['role']
	return result

# Function which encrypts the cookie
def encrypt(string):
	global cipher
	string = encode(string)
	for i in range(len(string), (len(string) / 16 + 1) * 16):
		string += '\x00'
	return cipher.encrypt(string)

# Function which decrypts a ciphertext
def decrypt(string):
	global cipher
	return cipher.decrypt(string)

# Creates an entry from a cookie. This is a process
# that would normally be server-side. Its split functionality
# is the one that we will try to abuse along ECB's deterministic
# nature.
def decode(string):
	string = decrypt(string)
	snip = string.split("&")
	obj = {}
	obj['email'] = snip[0].split('=')[1]
	obj['ID'] = snip[1].split('=')[1]
	obj['role'] = snip[2].split('\x00')[0].split('=')[1]
	return obj

# We want to obtain a block that contains the word 'admin' and nothing else
ciphertext = encrypt('A' * 10 + "admin\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

# And then isolate it
fragment = ciphertext[16 : 32]

# After that we generate a regular cookie, cut its role part
# and paste our 'admin' ciphertext snippet
main = encrypt('foooo@bar.com')
main = main[:len(main) - 16]
main += fragment

# When the server receives the tampered cookie it will
# generate an admin profile
plain = decode(main)
print(plain)
