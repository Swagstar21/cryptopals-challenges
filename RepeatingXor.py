"""
This is the code necessary to encrypt a variable-sized plaintext with a variable-sized key
with XOR in their bytes and then encoding the ciphertext using Hex
"""
key = 'ICE'
plaintext = 'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'
cyphertext = ''

# Each byte of the plaintext is encrypted with its corresponding key byte
for i in range(len(plaintext)):
	aux = ord(key[i % len(key)]) ^ ord(plaintext[i])
	cyphertext = cyphertext + chr(aux)

print ((cyphertext.encode('utf-8')).hex())