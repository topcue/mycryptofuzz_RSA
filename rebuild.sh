#!/bin/sh

clang++-8 rsa.cpp -o a -I /home/topcue/workspace/cryptopp -L /home/topcue/workspace/cryptopp -l cryptopp -fsanitize=address,fuzzer

# EOF

