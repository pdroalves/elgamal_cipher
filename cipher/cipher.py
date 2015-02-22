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

class Cipher:

	def __init__(self,keys=None):
		if keys:
			self.keys = keys
		return None

	def encrypt(self,x):
		return None

	def decrypt(self,c):
		return None

	def generate_keys(self,key_size):
		return None

	def has_keys(self):
		return True if self.keys and self.keys.has_key("pub") and self.keys.has_key("priv") else False

	def get_public_key(self):
		if self.keys is None:
			raise Exception("There is no keys!")
		if not self.keys.has_key("pub"):
			raise Exception("There is no public key!")
		
		return self.keys["pub"]

	def get_private_key(self):
		if self.keys is None:
			raise Exception("There is no keys!")		
		if not self.keys.has_key("priv"):
			raise Exception("There is no private key!")

		return self.keys["priv"]

	def add_to_public_key(self,name,value):
		if self.keys is None:
			raise Exception("There is no keys!")
		if not self.keys.has_key("pub"):
			raise Exception("There is no public key!")

		self.keys["pub"][name] = value

	def add_to_private_key(self,name,value):
		if self.keys is None:
			raise Exception("There is no keys!")	
		if not self.keys.has_key("priv"):
			raise Exception("There is no private key!")

		self.keys["priv"][name] = value