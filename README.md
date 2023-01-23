# Twisted ElGamal: ZKP-friendly Homomorphic PKE

## Overview

This is an implementation of twisted ElGamal. Twisted ElGamal PKE resembles standard exponent-version ElGamal PKE (also known as lifted ElGamal), but with a simple twist, i.e., switching the roles between key encapsulation and DEM key. The insight is that $F_{sk}(pk^r) = g^r$ constitutes a weak PRP over $\mathbb{G}$ based on the DDH assumption. 

Twisted ElGamal PKE is as secure and efficient as standard ElGamal. Moreover, it is zero-knowledge proofs friendly, particularly, the state-of-the-art Bulletproofs. We summarize the features of twisted ElGamal as below:

- additively homomorphic over $\mathbb{Z}_p$ 
- IND-CPA secure based on the DDH assumption
- zero-knowledge proofs friendly
- fast decryption: for 32-bit message space, decryption is less than 1ms with a 264 MB hash table

This makes twisted ElGamal extremely useful in numerous privacy-preserving setting. See the document in doc for more details. 

By the way, we also implement standard exponent ElGamal PKE for reference.   

## Specifications

- OS: MAC OS x64, Linux x64
- Language: C++
- Requires: OpenSSL


## Code Structure
- README.md

- CmakeLists.txt: cmake file

- /build: (after compile and execute) 
  * test_twisted_elgamal/test_elgamal: the resulting executable file
  * point2index.table: the hashmap used for DLOG algorithm (if this file does not exist, the program will generate one)


- /global: global.hpp --- define global variables


- /depend: dependent files
  * routines.hpp: related routine algorithms, such as serialization functions 
  * hash.hpp: implement an EC point to EC point hash function
  * print.hpp: print info for debug


- /src: source files
  * twisted_elgamal_pke.hpp: implement twisted ElGamal PKE, depending on calculate_dlog.hpp and routines.hpp
  * elgamal_pke.hpp: implement ElGamal PKE, depending on calculate_dlog.hpp and routines.hpp
  * calculate_dlog.hpp: implement Shanks DLOG algorithm


- /test: test files
  * test_elgamal.cpp: main program - test ElGamal PKE, include correctness and benchmark tests (both single thread and multi-thread)


- /doc: technical report of twisted ElGamal

## Install OpenSSL (On Linux)
download [openssl-master.zip](https://github.com/openssl/openssl.git), then
```
  $ mkdir openssl
  $ mv openssl-master.zip /openssl
  $ unzip openssl-master.zip
  $ cd openssl-master
  $ ./config shared
  $ ./make
  $ ./make test
  $ ./make install
```

## Compile and Run
```
  $ mkdir build && cd build
  $ cmake ..
  $ make
  $ ./test_twisted_elgamal && ./test_elgamal
```

## Parameter choices

- elliptic curve choice
  * The default elliptic curve is "NID_X9_62_prime256v1". 
    You can choose your favorite EC curve by specifying the curve_id (twisted_elgamal.hpp: line 158).


- message space choice
  * The default message space is [0, 2^32). 
    You can modify the message space by changing the variable <font color=red>MSG_LEN</font> in public parameter. 


- preprocessing choice
  * The default size of hashmap used for Shanks DLOG algorithm is roughly 264MB. 
    One could change its size by changing the variable <font color=red>MAP_TUNNING</font> in public parameters. 


- thread choice
  * The default thread number for parallel decryption is 4. You can adjust it to match the number of cores 
    of your CPU. One could change its by changing the variable <font color=red>DEC_THREAD_NUM</font> in public parameters. 

## APIs of Twisted ElGamal (single thread)
  * <font color=blue>global_initialize(int curve_id)</font>: initialize the OpenSSL environment
  * <font color=blue>global_finalize()</font>: finalize the OpenSSL environment
  * <font color=blue>Twisted_ElGamal_Setup(pp, MSG_LEN, MAP_TUNNING, DEC_THREAD_NUM)</font>: generate system-wide public parameters of twisted ElGamal
  * <font color=blue>Twisted_ElGamal_Initialize(pp)</font>: generate hash map for fast decryption
  * <font color=blue>Twisted_ElGamal_KeyGen(pp, keypair)</font>: generate a keypair
  * <font color=blue>Twisted_ElGamal_Enc(pp, pk, m, CT)</font>: encrypt message 
  * <font color=blue>Twisted_ElGamal_Dec(pp, sk, CT, m)</font>: decrypt ciphertext
  * <font color=blue>Twisted_ElGamal_ReRand(pp, pk, sk, CT, CT_new, r)</font>: re-randomize ciphertext with given randomness
  * <font color=blue>Twisted_ElGamal_HomoAdd(CT_result, CT1, CT2)</font>: homomorphic addition
  * <font color=blue>Twisted_ElGamal_HomoSub(CT_result, CT1, CT2)</font>: homomorphic subtraction
  * <font color=blue>Twisted_ElGamal_ScalarMul(CT_result, CT, k)</font>: scalar multiplication

We also provide parallel implementations, whose Enc, Dec, Scalar performances are better than those in single thread. 

## Tests 

- <font color=blue>test_twisted_elgamal()</font>: basic correctness test
  * random encryption and decryption test  
  * boundary encryption and decryption tests


- <font color=blue>benchmark_twisted_elgamal()</font>: collect the benchmark in single thread
  * setup
  * key generation
  * encryption
  * re-randomization
  * decryption
  * homomorphic addition
  * homomorphic subtract
  * scalar multiplication     


- <font color=blue>benchmark_parallel_twisted_elgamal()</font>: collect the benchmark in 2 thread
  * setup
  * key generation
  * encryption
  * re-randomization
  * decryption (4 thread)
  * homomorphic addition
  * homomorphic subtract
  * scalar multiplication 

---

## Updates
This library is obsoleted due to the inefficiency of MIRACL and complicated interfaces of OpenSSL. 
We refer to https://github.com/yuchen1024/Kunlun for a neat and efficient implementation. 

---

## License

This library is licensed under the [MIT License](LICENSE).

