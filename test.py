#!/usr/bin/python

# Copyright 2015 Pedro Alves

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import random
import unittest
from elgamal_cipher import ElGamal
import generate_prime as Prime

class TestSequenceFunctions(unittest.TestCase):
    def test_miller_rabin(self):
        # Miller-Rabin test gives no guarantee that a number is a truly prime.
        # However, it should give guarantee that a number isn't prime.
        #

        print "Test: Miller-Rabin"

        # Load the first 10.000 primes from http://primes.utm.edu/lists/small/10000.txt
        with open("10000primes.dat") as f:
            data = f.readlines()
            known_primes = [int(x) for x in data]

        higher = 104729 # higher known prime
        for n in xrange(10,higher):
            if not Prime.miller_rabin(n):
                # If our test says a number n isn't prime, we check if it really isn't in our known prime list
                self.assertFalse(n in known_primes)

    def test_generate_primes(self):
        # Ask for n primes and check if they are really primes
        n = 10000
        prime_order = 16
        with open("10000primes.dat") as f:
            data = f.readlines()
            known_primes = [int(x) for x in data]

        prime_candidates = []
        for i in range(n):
            prime_candidates.append(Prime.generate_large_prime(prime_order))

        right = 0
        wrong = 0
        for candidate in prime_candidates:
            if candidate in known_primes:
                right+=1
            else:
                wrong+=1
        self.assertTrue(float(wrong)/right <= 0.01) 
       

    def test_elgamal(self):
        #
        # Tests if this cipher can encrypt and decrypt all values up to 10**3
        #

        print "Test: ElGamal cipher"

        key_size = 256 # We use a smaller key than elgamal to be able to complete this test in less than 1 minute
        #test_range = 2**16
        test_range = 10**3

        cipher = ElGamal()
        cipher.generate_keys(key_size=key_size)
        for n in xrange(1,test_range):
            c,ke = cipher.encrypt(n)
            self.assertNotEqual(c,n)
            self.assertEqual(cipher.decrypt([c,ke]),n)
    
    def test_elgamal_exponential(self):
        #
        # Tests if this cipher can encrypt and decrypt all values up to 10**3
        #

        print "Test: ElGamal Exponencial cipher"

        key_size = 256 # We use a smaller key than elgamal to be able to complete this test in less than 1 minute
        #test_range = 2**16
        test_range = 10**3

        cipher = ElGamal(exponential_mode=True)
        cipher.generate_keys(key_size=key_size)
        lookup_table = cipher.generate_lookup_table(a=1,b=test_range)

        for n in xrange(1,test_range):
            c,ke = cipher.encrypt(n)
            self.assertNotEqual(c,n)
            self.assertEqual(lookup_table[cipher.decrypt([c,ke])],n)
            
    def test_deterministic_elgamal_A(self):
        m = 1564

        cipher = ElGamal()
        cipher.generate_keys(key_size=256)
        cipher.set_deterministic() # Choose r for me

        c = cipher.encrypt(m)
        self.assertEqual(c,cipher.encrypt(m))
    
    def test_deterministic_elgamal_B(self):
        m = 1565

        cipher = ElGamal()
        cipher.generate_keys(key_size=256)
        r = random.randrange(2,cipher.get_public_key()["p"])
        cipher.set_deterministic(r) # Choose r for me

        c = cipher.encrypt(m)
        self.assertEqual(c,cipher.encrypt(m))


if __name__ == '__main__':
    unittest.main()