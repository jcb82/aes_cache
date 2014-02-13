/*
 * encrypt.h
 * Joseph C. Bonneau
 * December 2005
 *
 * Wrapper functions around OpenSSL AES calls
 */

#include "aes.h"

#ifndef ENCRYPT_HEADER
#define ENCRYPT_HEADER

//length of AES key in bytes (128 bits)
#define KEY_LENGTH 16

//maximum time for normal encrpytions,
//cutoff below this value toreduce noise

//structure which holds info about key
typedef struct{  
  unsigned char key_byte[KEY_LENGTH];
  AES_KEY expanded;
  unsigned char encrypted_zero[16];
} key_data;

void encrypt(unsigned char * in, unsigned char * out, key_data * key);
void decrypt(unsigned char * in, unsigned char * out, key_data * key);
void read_encrypt_key(key_data * key, char * key_file);
void read_decrypt_key(key_data * key, char * key_file);
#endif
