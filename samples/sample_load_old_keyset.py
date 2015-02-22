#!/usr/bin/python

import sys
import json
import random
from time import time
from tempfile import TemporaryFile
sys.path.append("../")
from cipher.elgamal_cipher import ElGamal

elgamal = ElGamal()
print "Generating keys..."
keyset = elgamal.generate_keys()

value = 5
print "Encrypting %d" % value
c,ke = elgamal.encrypt(value)
print "%d encrypted to %d" % (value,c)

print "Dumping keyset to some file..."
# Dumps the keyset to some temporary file
f = TemporaryFile(mode="w+")
json.dump(keyset,f)
f.seek(0)

print "Destroying any reference to cipher object or keyset"
# Explicity destroys cipher object
elgamal = None
keyset = None

print "Loading keyset"
keyset = json.load(f)
elgamal = ElGamal(keys=keyset)

print "Decrypting..."
m = elgamal.decrypt(x=[c,ke])
print "Wow! We found %d" % m

print "Done."
