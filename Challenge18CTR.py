"""
Robert Panduru
2018
Another working mode for the AES. The bytes of the plaintext
are XOR'ed with a running counter.
"""

from Crypto.Cipher import AES
from random import randint
import base64
from Crypto.Util import Counter

# We will encrypt this string
string = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
string = base64.b64decode(string)

# The key is irrelevant
# CTR doesn't use it
key = "YELLOW SUBMARINE"

# Initialize the counter and the encrypter
ctr = Counter.new(nbits=64,  prefix='\x00\x00\x00\x00\x00\x00\x00\x00', initial_value=0, little_endian=True)
cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
string = cipher.encrypt(string)
print(string)