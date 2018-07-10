"""
Robert Panduru
2018
PKCS#7 is a padding scheme used to lengthen a message
to a specific size in order to be encrypted. It is typically
used in web applications.
"""

text = "YELLOW SUBMARINE"

length = len(text)
wantedSize = int(raw_input())

# The padding is compulsary. No message can remain without
# padding
if wantedSize == length:
	wantedSize += 16

# The character that is appended has his ASCII value
# equal to the number the times it is appended
for i in range(length, wantedSize):
	text = text + chr(wantedSize - length)

print(text)