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
import getopt
import random
import json
import os
import generate_prime as Prime
from cipher import Cipher

#randrange is mersenne twister and is completely deterministic
#unusable for serious crypto purposes

class ElGamal(Cipher):

	def __init__(self,keys=None,exponential_mode=False):
		self.exponential_mode = exponential_mode
		Cipher.__init__(self,keys)

	def generate_keys(self,key_size=1024):
		#
		# Public key: (p,alpha,beta)
		# Private key: (d)
		#
		p = None
		while p is None:
			try:
				p = Prime.generate_large_prime(key_size)
			except Exception,err:
				print err


		alpha = random.randrange(1,p) # if |G| is prime, then all elements a not 1 \in G are primitives
		d = random.randrange(2,p-1)# from 2 to p-2
		beta = pow(alpha,d,p)

		self.keys = {"pub":{
					"p":p,
					"alpha":alpha,
					"beta":beta},
				"priv":{
				 "d":d
				 }
			   }

		return self.keys

	def set_deterministic(self,km=None):
		if km is None:
			pub = Cipher.get_public_key(self)
			i = random.randrange(2,pub["p"]-1)
			km = pow(pub["beta"],i,pub["p"])
		Cipher.add_to_public_key(self,"km",km)
		return km

	def encrypt(self,m):
		#
		# Encrypts a single integer
		#

		assert self.__is_int(m)

		pub = Cipher.get_public_key(self)

		assert pub.has_key("p")
		assert pub.has_key("alpha")
		assert pub.has_key("beta")

		p = pub["p"]
		alpha = pub["alpha"]
		beta = pub["beta"]
		km = pub["km"] if pub.has_key("km") else None

		if self.exponential_mode:
			if m < 0:
				x = self.__modinv(pow(alpha,-m,p),p)
			else:
				x = pow(alpha,m,p)
		else:
			x = m

		if not km:
			i = random.randrange(2,p-1)
			ke = pow(alpha,i,p)
			km = pow(beta,i,p)

			c = (x*km) % p
			return c,ke
		else:
			c = (x*km) % p
			return c

	def decrypt(self,x):
		#
		# Decrypts a single integer
		#
		pub = Cipher.get_public_key(self)
		priv = Cipher.get_private_key(self)

		assert pub.has_key("p")
		assert priv.has_key("d")

		p = pub["p"]
		d = priv["d"]
		if (type(x) == list or type(x) == tuple) and len(x) == 2:
			c = x[0]
			ke = x[1]
		else:
			c = x
		km = pub["km"] if pub.has_key("km") else pow(ke,d,p)

		inv = self.__modinv(km,p)

		return c*inv % p

	def generate_lookup_table(self,a=0,b=10**3):
		#
		# Receives an base g, prime p, a public key pub and a interval [a,b],
		# computes and encrypts all values g**i mod p for a <= i <= b and
		# returns a lookup table
		#
		pub = Cipher.get_public_key(self)

		alpha = pub["alpha"]
		p = pub["p"]

		table = {}
		for i in xrange(a,b):
			c = pow(alpha,i,p)
			table[c] = i
		return table

	def __modinv(self,x,p):
		#
		# Computes the moduler inversion of x ** p-2 mod p,
		# for p prime
		#
		#return pow(x,p-2,p)
		return pow(x,p-2,p)

	def __is_int(self,x):
		try:
			int(x)
			return True
		except:
			return False

	def __encode(self,plaintext):
		# Receives a plaintext, string or not.
		# Converts it to string (if it is not) and returns a tuple of integers

		byte_array = bytearray(str(plaintext), 'utf-16')

		#encoded is the array of integers mod p
		encoded = []

		#each encoded integer will be a linear combination of k message bytes
		#k must be the number of bits in the prime divided by 8 because each
		#message byte is 8 bits long

		iNumBits = int(math.ceil(math.log(self.keys["pub"]["p"])/math.log(2)))
		k = iNumBits//8

		#j marks the jth encoded integer
		#j will start at 0 but make it -k because j will be incremented during first iteration
		j = -1 * k
		#num is the summation of the message bytes
		num = 0
		#i iterates through byte array
		for i in range( len(byte_array) ):
		        #if i is divisible by k, start a new encoded integer
		        if i % k == 0:
		                j += k
		                num = 0
		                encoded.append(0)
		        #add the byte multiplied by 2 raised to a multiple of 8
		        encoded[j//k] += byte_array[i]*(2**(8*(i%k)))

		#example
		        #if n = 24, k = n / 8 = 3
		        #encoded[0] = (summation from i = 0 to i = k)m[i]*(2^(8*i))
		        #where m[i] is the ith message byte

		#return array of encoded integers
		return tuple(encoded)

	def __decode(self,encoded_plaintext):
		# Receives a encoded plaintext, decodes and returns as string
		#bytes array will hold the decoded original message bytes
		bytes_array = []

		#same deal as in the encode function.
		#each encoded integer is a linear combination of k message bytes
		#k must be the number of bits in the prime divided by 8 because each
		#message byte is 8 bits long
		iNumBits = int(math.ceil(math.log(self.keys["pub"]["p"])/math.log(2)))
		k = iNumBits//8

		#num is an integer in list encoded_plaintext
		# for num in encoded_plaintext:
		num = int(encoded_plaintext)
		#get the k message bytes from the integer, i counts from 0 to k-1
		for i in range(k):
		        #temporary integer
		        temp = num
		        #j goes from i+1 to k-1
		        for j in range(i+1, k):
		                #get remainder from dividing integer by 2^(8*j)
		                temp = temp % (2**(8*j))
		        #message byte representing a letter is equal to temp divided by 2^(8*i)
		        letter = temp // (2**(8*i))
		        #add the message byte letter to the byte array
		        bytes_array.append(letter)
		        #subtract the letter multiplied by the power of two from num so
		        #so the next message byte can be found
		        num = num - (letter*(2**(8*i)))

		#example
		#if "You" were encoded.
		#Letter        #ASCII
		#Y              89
		#o              111
		#u              117
		#if the encoded integer is 7696217 and k = 3
		#m[0] = 7696217 % 256 % 65536 / (2^(8*0)) = 89 = 'Y'
		#7696217 - (89 * (2^(8*0))) = 7696128
		#m[1] = 7696128 % 65536 / (2^(8*1)) = 111 = 'o'
		#7696128 - (111 * (2^(8*1))) = 7667712
		#m[2] = 7667712 / (2^(8*2)) = 117 = 'u'

		decodedText = bytearray(b for b in bytes_array).decode('utf-16')

		return decodedText
