ElGamal Cryptosystem
========================================

#About

This is a Python implementation of ElGamal cryptosystem. Our purpose is provide a correct, efficient and very easy to use; code. 

#Features
- Key generation process is completely encapsulated, including primes generation.
- Support to deterministic and exponential mode.

#Usage

Now we will provide very simple and tiny examples of how to use this library. The correctness of the methods can be evaluated by test.py.

### Basics
First, import and instantiate the cipher class.

```python
from elgamal_cipher import ElGamal
elgamal = ElGamal()
```

The construction class also supports "keys" parameter, that receives a key set; if you have it. Otherwise, you have to generate the key set using generate_keys() method. By default, it uses 1024 bits primes. You can change that through key\_size parameter.

```python
elgamal.generate_keys()
```

With the keys computed (or loaded), use encrypt() method to encrypt something.

```python
c,ke = elgamal.encrypt(5)
```

It will store the cipher in c and the ephemeral key in ke. To decrypt, use decrypt() method. It receives a list with c and ke, or just the integer c. In this case, you should guarantee that you are running on exponential mode, so km variable exists in public key set.

```python
m = elgamal.decrypt(x=[c,ke])
```

### Complete example

For a simple encrypt/decrypt routine:

```python
from elgamal_cipher import ElGamal
elgamal = ElGamal()
elgamal.generate_keys()
c,ke = elgamal.encrypt(5)
m = elgamal.decrypt(x=[c,ke])
```

If you need to load a previous key set from some file:
```python
keys = json.load(f)
elgamal = ElGamal(keys=keys)
```

For deterministic mode:
```python
elgamal = ElGamal()
elgamal.generate_keys()
elgamal.set_deterministic()
```

For exponential mode:
```python
elgamal = ElGamal(exponential_mode=True)
elgamal.generate_keys()

# To recover the message m in a interval [a,b], we need to first generates a lookup table
lookup_table = elgamal.generate_lookup_table(a,b)

c,ke = elgamal.encrypt(5)
gm = elgamal.decrypt(x=[c,ke])

# Now we apply a lookup over lookup_table to find m
m = lookup_table[gm]
```

#License
Copyright 2015 Pedro Alves

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

--
2015 - by Pedro Alves

pdroalves (at) gmail.com