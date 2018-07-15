"""
Robert Panduru
2018
A vulnerability of the Mersenne Twister is that the
function that extracts the values from the number array
is invertible by using masks and obtaining the bits
that don't change during the operations. After obtaining
the untempered values we can use them to rig a new
generator that will extract the exact same values as
earlier, practically replicating the output.
"""

from random import randint
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
	return y

# Will return the value from the MT array
# from which the output was derived.
# Pretty complicated one...
def untemper(output):
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
	
	y = output
	x = y & 0xFFFC0000
	z = (y ^ x) ^ (y >> l)
	y = x + z
	x = y & 0x0001FFFF
	z = (y ^ x) ^ ((y << t) & c)
	y = x + z

	z = y & 0x7F
	last = z
	y = y >> s
	tmp = b >> s
	i = 0
	for i in range(1, 32 / s + 1):
		z += (((y & 0x7F) ^ (last & (tmp & 0x7F))) << (s * i))
		last = (y & 0x7F) ^ (last & (tmp & 0x7F))
		y = y >> s
		tmp = tmp >> s 

	y = z
	z = y & 0xFFE00000
	last = z
	y = y & 0x1FFFFF
	y = y << u
	tmp = d
	tmp = tmp & 0x1FFFFF
	tmp = tmp << u
	
	i = 0
	for i in range(1, 32 / u + 1):
		z += ((y & 0xFFE00000) ^ (last & (tmp & 0xFFE00000))) >> (u * i)
		last = (y & 0xFFE00000) ^ (last & (tmp & 0xFFE00000))
		y = y & 0x1FFFFF
		y = y << u
		tmp = tmp & 0x1FFFFF
		tmp = tmp << u

	y = z

	return y & 0xFFFFFFFF

# Seeding the generator with a random seed
seed_MT(randint(1000, 9999))

result = []
clone = []
resultOfClone = []
# Extracting the numbers form the PRNG and
# populating the array of the "rigged" one
for i in range(n):
	result.append(extract())
	clone.append(untemper(result[i]))

print("Are the arrays of the two generators the same?")
print(clone == MT)

# Extracting the values of the "rigged" generator
MT = clone
index = 0
for i in range(n):
	resultOfClone.append(extract())

print("Are the predicted values the same?")
print(resultOfClone == result)