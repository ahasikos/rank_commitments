**rankcommitments** is a C++ library for interactive zero-knowledge proofs for: the knowledge of a valid opening of a 
committed value, and that the valid openings of three committed values satisfy a given linear relation, and, more 
generally, any bitwise relation.

This project is an outcome of the paper __Enhancing Code Based Zero-knowledge Proofs using Rank Metric__ (to be) published at 
CANS 2020. The objective of this work is to implement and compare:
1. The LPN variant by Jain et. al https://eprint.iacr.org/2012/513.pdf
2. The Rank variant by Bellini et. al (this work)

# Prerequisites:
1. OpenSSL
2. CMake > 3.14

# Build
You will need to provide paths to OpenSSL _include_ and _lib_ directories

````
$ mkdir build
$ cd build
$ cmake -DOPENSSL_ROOT_DIR=<path_to_openssl_root_dir> ..
````
# Run Tests
To run the tests, build the library and run:

````
$ build/tests/test_rankcommitment
````
