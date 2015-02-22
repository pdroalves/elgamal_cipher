#!/usr/bin/python

import sys
import random
from time import time
sys.path.append("../")
from cipher.elgamal_cipher import ElGamal

elgamal = ElGamal()
print "Generating keys..."
elgamal.generate_keys()

value = 5
print "Encrypting %d" % value
c,ke = elgamal.encrypt(value)
print "%d encrypted to %d" % (value,c)

print "Decrypting..."
m = elgamal.decrypt(x=[c,ke])
print "Wow! We found %d" % m

print "Done."
