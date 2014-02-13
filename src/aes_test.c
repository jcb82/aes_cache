/*
 * aes_test.c
 * Joseph C. Bonneau
 * December 2005
 *
 * Test speed, correctness of aes implementation
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include "encrypt.h"
#include "key_revert.h"
#include "cache_evict.h"

#define DEFAULT_TRIALS 0xffffff

//#define VERBOSE

int main(int argc,char **argv)
{  

  key_data key;

  double total_encrypt_time = 0;
  double total_decrypt_time = 0;
  unsigned int min_encrypt = TIME_CUTOFF;
  unsigned int max_encrypt = 0;
  unsigned int min_decrypt = TIME_CUTOFF;
  unsigned int max_decrypt = 0;

  unsigned int timing = 0;
  unsigned char buffer[16];
  unsigned char plaintext[16];

  int i, j, trials;

  if (!argv[1] ){
    printf("\nusage: aes_test key_file num_tests");
    return -1;
  }

  read_encrypt_key(&key, argv[1]);

  if(argv[2])
    trials = atoi(argv[2]);

  else
    trials = DEFAULT_TRIALS;

  printf("\nTesting AES, key \"%s\", %d trials", argv[1], trials);

  for (j = 0; j < 16;++j) 
    buffer[j] = plaintext[j] = random();

#ifdef VERBOSE
   printf("\nINPUT:", i + 1);
  for(j = 0; j < 16; j++)
    printf(" %02x", buffer[j]);
#endif
  for(i  = 0; i < trials; i++){
    timing = timestamp();
    encrypt(buffer, buffer, &key);
    timing = timestamp() - timing;

    //do not record timings above cutoff 
    if (timing <  TIME_CUTOFF){
      total_encrypt_time += timing;

      if(timing < min_encrypt)
	min_encrypt = timing;
      
      if(timing > max_encrypt)
	max_encrypt = timing;
    }
#ifdef VERBOSE
  printf("\nE %i:", i + 1);
  for(j = 0; j < 16; j++)
    printf(" %02x", buffer[j]);
 #endif
  }

  #ifdef VERBOSE
  printf("\nMIDDLE:");  
  for(j = 0; j < 16; j++)
    printf(" %02x", buffer[j]);
 #endif
  read_decrypt_key(&key, argv[1]);

  for(i  = 0; i < trials; i++){
    timing = timestamp();
    decrypt(buffer, buffer, &key);
    timing = timestamp() - timing;

    //do not record timings above cutoff 
    if (timing <  TIME_CUTOFF){
      total_decrypt_time += timing;

      if(timing < min_decrypt)
	min_decrypt = timing;
      
      if(timing > max_decrypt)
	max_decrypt = timing;
    }
    #ifdef VERBOSE
    printf("\nD %i:", trials - i);
    for(j = 0; j < 16; j++)
      printf(" %02x", buffer[j]); 
#endif
  }

#ifdef VERBOSE
  printf("\nOUTPUT:");
  for(j = 0; j < 16; j++)
    printf(" %02x", buffer[j]);
 #endif
  int correct = 1;

  for(i = 0; i < 16; i++)
    if(buffer[i] != plaintext[i])
      correct = 0;

  if(correct)
    printf("\n*Correctness test succeeded*\n");
  else
    printf("\n*Correctness test failed*\n");

  printf("\nStats for %d encryptions: %0.5f average, %d min, %d max",
	 trials, (total_encrypt_time / trials), min_encrypt, max_encrypt);

  printf("\nStats for %d decryptions: %0.5f average, %d min, %d max",
	 trials, (total_decrypt_time / trials), min_decrypt, max_decrypt);
}
