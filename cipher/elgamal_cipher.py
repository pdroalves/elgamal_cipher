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
