"""
Robert Panduru
2018
The long text underneath was encrypted using the previous method and
all the lines were encrypted using the same key. Thus, the bytes
that are in the same column of the text were all obtained by XOR'ing
with the same byte. In order to determine the size of the key our
best bet is to analyse the entropy given by different key sizes.
The key that produces the least amount of entropy ie. the smallest
number of differing bits is most likely to be the key. This step is
not compulsary but reduces the overall number of operations required
to decipher the text. After finding the key size, the text can be
transposed and the columns deciphered by character frequency (the famous
ETAOIN SHRDLU). The only thing left to do is to transpose the text again.
"""

import base64

text2 = """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
""".encode("utf-8")

# It was obviously encrypted in base 64
text = (base64.b64decode(text2))

# It computes the number of different bits in two string
# by XOR'ing each byte from the strings and then counting
# how many powers of 2 the result divides
def hammingDistance(str1, str2):
	minimum = min(len(str1), len(str2))
	distance = 0
	for i in range(max(len(str1), len(str2))):
		if len(str1) >= len(str2):
			aux = (str1[i]) ^ (str2[i % minimum])
		else:
			aux = (str1[i % minimum]) ^ (str2[i])
		for j in range(7, -1, -1):
			if aux >= (2 ** j):
				distance = distance + 1
				aux = aux - (2 ** j)
	return distance

# a large value for the minimum hamming distance obtained
# so far
minim = 300000

for keySize in range(2, 41):
	# We take 4 strings with a specific size and try
	# to find their entropy normalized by their size
	str1 = text[0 : keySize]
	str2 = text[keySize : 2 * keySize]
	str3 = text[2 * keySize : 3 * keySize]
	str4 = text[3 * keySize : 4 * keySize]
	total = 0
	distance = hammingDistance(str1, str2)
	distance = 1.0 * distance / keySize
	total += distance
	distance = hammingDistance(str1, str3)
	distance = 1.0 * distance / keySize
	total += distance
	distance = hammingDistance(str1, str4)
	distance = 1.0 * distance / keySize
	total += distance
	distance = hammingDistance(str2, str3)
	distance = 1.0 * distance / keySize
	total += distance
	distance = hammingDistance(str2, str4)
	distance = 1.0 * distance / keySize
	total += distance
	distance = hammingDistance(str3, str4)
	distance = 1.0 * distance / keySize
	total += distance
	total = total / 6
	if total < minim:
		minim = total
		key = keySize

# We create blocks with the size we found earlier
block = []
for i in range(0, int(len(text) / key)):
	block.append(text[i * key : (i + 1) * key])

block.append(text[int(len(text) / key) * key:])

# And then transpose them
transposedBlock = []

for i in range(0, key):
	transposedBlock.append([])
	for j in range(0, len(block)):
		if i < len(block[j]):
			transposedBlock[i].append(block[j][i])

resultBlock = []

# It is time to determine the actual key
keyString = ""

for i in range(0, key):
	# Big error in order to find the correct Vigenere
	# offset used
	resultBlock.append([0] * len(transposedBlock[i]))
	error = 100000000
	# Iterate though all possible values of a byte
	for j in range(0, 256):
		aux = [0] * len(transposedBlock[i])
		nrTotal = 0
		nrE = 0
		nrT = 0
		nrA = 0
		nrSpace = 0
		for k in range(0, len(transposedBlock[i])):
			# Record each time a frequent character is found 
			aux[k] = transposedBlock[i][k] ^ j
			nrTotal += 1
			if aux[k] == ord('E') or aux[k] == ord('e'):
				nrE += 1
			if aux[k] == ord('T') or aux[k] == ord('t'):
				nrT += 1
			if aux[k] == ord('A') or aux[k] == ord('a'):
				nrA += 1
			if aux[k] == ord(' '):
				nrSpace += 1
			aux[k] = chr(aux[k])
		# The heuristic with which we differentiate the obtained
		# plaintexts is by summing the squares of the differences
		# between the median frequencies of the characters and the
		# perceived frequency.
		errortmp = (12 - nrE) ** 2 + (9 - nrA) ** 2 + (8 - nrT) ** 2 + (17 - nrSpace) ** 2
		if errortmp < error:
			error = errortmp
			resultBlock[i] = aux
			probable = chr(j)
	keyString += probable

# The found key
print(keyString)

text = ""

# Time to reassemble the plaintext
for i in range(len(block)):
	aux = ""
	for j in range(key):
		if (i < len(resultBlock[j])):
			aux += resultBlock[j][i]
	text += aux

print(text)