"""
Robert Panduru
2018
Using a random generator to generate the first number
of a counter can be a good idea if the seed is a large
number. Unfortunately 16 bits can't define a large enough
number to make it secure. The plaintext is generated by
the attacker and the goal is to find the seed forementioned.
A way to go is to try a brute force attack by iterating
through all the possibilities of the seed and choose the one
that generates a plaintext which contains our plaintext bytes.
"""

from Crypto.Cipher import AES
from random import randint
from random import randint
import time
import calendar

w = 32
n = 624
m = 397
r = 31
a = 0x9908B0DF
u = 11
d = 0xFFFFFFFF
s = 7
b = 0x9D2C5680
t = 15
c = 0xEFC60000
l = 18
f = 1812433253

MT = [0] * n
index = n + 1
lower_mask = (1 << r) - 1
upper_mask = (~lower_mask) & (0xFFFFFFFF)

def seed_MT(seed):
	global MT
	global index
	global f
	global w
	index = n
	MT[0] = seed
	for i in range(1, n):
		MT[i] = (f * (MT[i - 1] ^ (MT[i - 1] >> (w - 2))) + i) & (0xFFFFFFFF)

def twist():
	global n
	global MT
	global lower_mask
	global upper_mask
	global m
	global index
	global a
	for i in range(n - 1):
		x = MT[i] & upper_mask + (MT[(i + 1) % n] & lower_mask)
		xA = x >> 1
		if x % 2 != 0:
			xA = xA ^ a
		MT[i] = MT[(i + m) % n] ^ xA
	index = 0

def extract():
	global index
	global n
	global MT
	global u
	global s
	global t
	global l
	global d
	global b
	global c
	global l
	if index >= n:
		if index > n:
			print("Not seeded")
			return
		twist()
	y = MT[index]
	y = y ^ ((y >> u) & d)
	y = y ^ ((y << s) & b)
	y = y ^ ((y << t) & c)
	y = y ^ (y >> l)
	index += 1
	return y & 0xFFFFFFFF

def counter():
	string = ''
	for i in range(16):
		string += chr(extract() % 256)
	return string

# Something easy to spot
string = "A" * 14
for i in range(randint(1, 10)):
	string = chr(randint(0, 255)) + string

# Random seed
seed = randint(0, 2 ** 16 - 1)
seed_MT(seed)
print(seed)

cipher = AES.new("\x00" * 16, AES.MODE_CTR, counter=counter)
ciphertext = cipher.encrypt(string)

# Time to heat up the precessor and look for the 14 A's
for i in range(0, 2 ** 16):
	seed_MT(i)
	cipher = AES.new("\x00" * 16, AES.MODE_CTR, counter=counter)
	plaintext = cipher.encrypt(ciphertext)
	if plaintext[len(plaintext) - 14 :] == 'A' * 14:
		print(plaintext)
		print("The seed is %s." % (i))
		break