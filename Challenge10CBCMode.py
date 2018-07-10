"""
Robert Panduru
2018
Another operating mode for AES. Slightly more secure
because its scheme. Every block is XOR'ed against
the previous block. The first one is XOR'ed against
an Initialization Vector.
"""

import base64
from Crypto.Cipher import AES

# Here is the file 
# https://cryptopals.com/static/challenge-data/10.txt
with open("input.txt") as file:
	text = file.read()
	text = base64.b64decode(text)

IV = "\x00" * 16
decipher = AES.new("YELLOW SUBMARINE", AES.MODE_CBC, IV)
print(decipher.decrypt(text))
