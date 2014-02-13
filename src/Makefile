####
# Makefile for timing attacks and key description utility
# Joseph Bonneau, December 2005
####

CXX = gcc
CXX_FLAGS = -g -Wall
#V9_FLAG = -mcpu=v9
V9_FLAG = 
LD_FLAGS =
AES_FILE = none_aes_core.c

default: aes_attack describe_key aes_test

aes_attack: aes_attack.c 
	$(CXX) $(V9_FLAG) -lm -O3 -o aes_attack aes_attack.c alg.c key_revert.c $(AES_FILE) encrypt.c cache_evict.c

describe_key: describe_key.c 
	$(CXX) $(V9_FLAG) -lm -O3 -o describe_key describe_key.c encrypt.c $(AES_FILE) key_revert.c

aes_test: aes_test.c 
	$(CXX) $(V9_FLAG) -lm -O3 -o aes_test aes_test.c encrypt.c cache_evict.c $(AES_FILE)

clean :
	\rm -fr *.o *~ aes_attack describe_key aes_test