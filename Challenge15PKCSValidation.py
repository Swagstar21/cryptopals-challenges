"""
Robert Panduru
2018
This is a simple padding validation routine.
It simply checks if at the end of the string
there are the same number of padding bytes as
the value of any of them.
"""

def paddingValidation(string):
	nr = 0
	byte = string[len(string) - 1]
	value = ord(byte)
	for i in range(len(string) - 1, len(string) - 1 - value, -1):
		if string[i] != byte:
			return "Bad padding"
		else:
			nr += 1
	return string[:len(string) - nr]

print(paddingValidation("ICE ICE BABYYYY\x01"))