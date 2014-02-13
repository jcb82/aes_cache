/*
 * encrypt.c
 * Joseph C. Bonneau
 * December 2005
 *
 * Wrapper functions around OpenSSL AES calls
 */

#include "encrypt.h"
#include <stdio.h>

void encrypt(unsigned char * in, unsigned char * out, key_data * key){
  AES_encrypt(in, out ,&key->expanded);
}

void decrypt(unsigned char * in, unsigned char * out, key_data * key){
  AES_decrypt(in, out ,&key->expanded);
}

void read_encrypt_key(key_data * key, char * key_file){
  
  char open_type = 'r';


  FILE * kf = fopen(key_file, &open_type);
  
  if(kf == NULL){
    printf("\nCouldn't open file: %s",
	  key_file);
    exit(104);
  }

  int bread = fread(key->key_byte,1, KEY_LENGTH, kf);

  if (bread < KEY_LENGTH) 
    exit(105);

  int j;

  unsigned char temp_key[KEY_LENGTH];

  AES_set_encrypt_key(key->key_byte,128,&key->expanded);

  fclose(kf);
}

void read_decrypt_key(key_data * key, char * key_file){
  
  char open_type = 'r';


  FILE * kf = fopen(key_file, &open_type);
  
  if(kf == NULL){
    printf("\nCouldn't open file: %s",
	  key_file);
    exit(104);
  }

  int bread = fread(key->key_byte,1, KEY_LENGTH, kf);

  if (bread < KEY_LENGTH) 
    exit(105);

  int j;

  unsigned char temp_key[KEY_LENGTH];

  AES_set_decrypt_key(key->key_byte,128,&key->expanded);

  fclose(kf);
}
