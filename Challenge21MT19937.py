"""
Robert Panduru
2018
This is an implementation of the Mersenne Twister pseudorandom
number generator. It is the most popular PRNG's currently used
and even Python's random library is based on it.
"""

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
