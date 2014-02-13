/*
 * describe_key.c
 * Joseph C. Bonneau
 * December 2005
 *
 * Utility function to describe a 16-byte file representing
 * a 128-bit AES key.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "encrypt.h"
#include "constants.h"
#include "key_revert.h"

unsigned char zero[16]= {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				   0, 0, 0};


int main(int argc,char **argv)
{  

  key_data key;


  if (!argv[1]){
    printf("\nusage: describe_key key_file");
    return -1;
  }

  read_encrypt_key(&key, argv[1]);

  int i;

  //actual key
  printf("Key bytes: \n");
  for(i = 0; i < KEY_LENGTH; i++)
    printf("%02x ", key.key_byte[i]);

  //last 16 bytes of expanded key
  printf("\nOutput whitening key words:\n");
  printf("%08x  %08x  %08x  %08x ", 
	key.expanded.rd_key[40], 	
	 key.expanded.rd_key[41], 
	 key.expanded.rd_key[42], 
	 key.expanded.rd_key[43]);

    //last 16 bytes of expanded key
  printf("\nExpanded key (encryption):\n");

  for(i = 0; i <= 10; i++)
  printf("\n%08x  %08x  %08x  %08x ", 
	key.expanded.rd_key[4 * i], 	
	 key.expanded.rd_key[4 * i + 1], 
	 key.expanded.rd_key[4 * i + 2], 
	 key.expanded.rd_key[4 * i + 3]);

  unsigned char encrypted_zero[16];

  encrypt(zero, encrypted_zero, &key);
  
  //encryption of a block of 128 zeroes
  printf("\nEncryption of zero block: \n");
  for(i = 0; i < KEY_LENGTH; i++)
    printf("%02x ", encrypted_zero[i]);
  
  unsigned char * opb = (unsigned char *) ( key.expanded.rd_key + 40);
    
  unsigned char fixed[16];
  
  printf("\nByte-wise opb: \n");

  for(i = 0; i < KEY_LENGTH; i++){
#ifdef SPARC
    fixed[i] = opb[i];
#else
    fixed[i] = opb[i^3];
#endif
    printf(" %02x ", fixed[i]);
  }

 revert_key(fixed, encrypted_zero);
  
  printf("\nReverted key: \n");
  for(i = 0; i < KEY_LENGTH; i++)
    printf("%02x ", encrypted_zero[i]);

  printf("\n");
      
  read_decrypt_key(&key, argv[1]);

  printf("\nExpanded key (decryption):\n");

  for(i = 0; i <= 10; i++)
  printf("\n%08x  %08x  %08x  %08x ", 
	key.expanded.rd_key[4 * i], 	
	 key.expanded.rd_key[4 * i + 1], 
	 key.expanded.rd_key[4 * i + 2], 
	 key.expanded.rd_key[4 * i + 3]);

  decrypt(zero, encrypted_zero, &key);

 //decryption of a block of 128 zeroes
  printf("\nDecryption of zero block: \n");
  for(i = 0; i < KEY_LENGTH; i++)
    printf("%02x ", encrypted_zero[i]);

  return 0;
}
