"""
Robert Panduru
2018
Except the implementation from earlier of the MT the
program will choose a timestamp from the very near future
and will use it as a seed for the PRNG and return the
first output generated. After that we will iterate over
a small time interval in search of the seed, knowing a
timestamp was used as a seed. When the extract() will
return the value we had from earlier we will know that
this is the seed 
"""

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

def routine():
	time1 = randint(40, 100)
	seed = calendar.timegm(time.gmtime())
	seed_MT(seed)
	number = extract()
	time2 = randint(40, 100)
	print(seed)
	return number


chosen = routine()
time = calendar.timegm(time.gmtime())
for i in range(200):
	seed_MT(time - i)
	number = extract()
	if number == chosen:
		print("The chosen seed was %d" % (time - i))
		break