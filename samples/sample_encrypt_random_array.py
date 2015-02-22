#!/usr/bin/python

import sys
import random
from time import time
sys.path.append("../")
from cipher.elgamal_cipher import ElGamal

# Instantiate a cipher object
cipher = ElGamal()
cipher.generate_keys()

# Generates a random array of random length
print "Generating random array"
random_array = range(random.randint(0,1000))
random.shuffle(random_array)
print "Generated an array of length %d" % (len(random_array))

# Encrypts the array
print "Encrypting array"
start = time()
encrypted_random_array = [cipher.encrypt(x) for x in random_array]
end = time()
print "Array encrypted in %f s" % (end-start)

# Decrypts the array
print "Decrypting array"
start = time()
decrypted_random_array = [cipher.decrypt(x) for x in encrypted_random_array]
end = time()
print "Array decrypted in %f s" % (end-start)

print "Done"
