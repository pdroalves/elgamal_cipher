#!/usr/bin/python

import sys
import random
from time import time
sys.path.append("../")
from cipher.elgamal_cipher import ElGamal

elgamal = ElGamal(exponential_mode=True)
print "Generating keys..."
elgamal.generate_keys()

# To recover the message m in a interval [a,b], we need to first generates a lookup table
lookup_table = elgamal.generate_lookup_table(0,10)

value = 5
print "Encrypting %d" % value
c1,ke1 = elgamal.encrypt(value)
print "%d encrypted to %d" % (value,c1)

print "Encrypting again %d" % value
c2,ke2 = elgamal.encrypt(value)
print "%d encrypted to %d" % (value,c2)

print "Decrypting..."
gm = elgamal.decrypt(x=[c1,ke1])
m = lookup_table[gm]
print "Wow! We found %d" % m

print "Done."
