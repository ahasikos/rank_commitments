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

# Dependencies
This project uses the following libraries which are installed locally during the execution of cmake:

1. NTL https://www.shoup.net/ntl/
2. gf2x https://gitlab.inria.fr/gf2x/gf2x#the-gf2x-software-library

# Build
You will need to provide paths to OpenSSL _root_ directory. Also ensure that you build libgf2x and libntl 
(in this order) before anything else as these two libraries are used everywhere throughout the code.

From the terminal:
````
$ mkdir build
$ cd build
$ cmake -DOPENSSL_ROOT_DIR=<path_to_openssl_root_dir> ..
$ make libgf2x
$ make libntl
$ make
````

From CLion:
1. Build target **libgf2x**
2. Build target **libntl**
3. Build target **test_rankcommitment** or any other.

# Run Tests
To run the tests, build the library and run:

````
$ build/src/test/test_rankcommitment
````
