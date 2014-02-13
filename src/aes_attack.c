#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include "encrypt.h"
#include "key_revert.h"
#include "cache_evict.h"
#include "constants.h"
#include "alg.h"
#include "aes_attack.h"

//Look at a maximum of 2^28 timings
#define MAX_STUDY 0x100000000
#define BUF_SIZE 0x400000

#define AVG_SAMPLE_SIZE 0x100

#define CLIP_RATIO 2

unsigned char zero[16]= {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

int USE_RANDOM_KEY = 0;


int write_data(timing_pair * data, char * filename, int inputs, char open_type)
{
  int i, j;

  FILE * out = fopen(filename, &open_type);

  if(out == NULL){
    printf("\nCould not open file: %s", filename);
    return;
  }

  printf("\nPrinting %d samples to file %s, mode %c", 
	 inputs, filename, open_type);

  int size = sizeof ( timing_pair);
  printf("Size = %d x %d = %d", inputs, size, inputs * size);

  int printed = fwrite(data, size, inputs, out);
  
  printf(" [%d printed] ", printed);

   if(fclose(out) != 0)
     printf("Error occured...");  

   return printed;
}

void generate_samples(timing_pair * buffer, key_data * key){

  int i;

  for(i = 0; i < BUF_SIZE; i++){

    cache_evict();

    timing_sample(key, buffer + i);

  }
}

void output_timings(char * output_file, timing_pair * buffer,
            int num_timings, key_data * key)
{     
  int written = 0;

  while(written < num_timings){
    
    generate_samples(buffer, key);

    int to_write = BUF_SIZE;

    if(to_write + written > num_timings)
      to_write = num_timings - written;
	
    if(!written)
      written += write_data(buffer, output_file, to_write, 'w');
    else 
      written += write_data(buffer, output_file, to_write, 'a');
  }	

  printf("\n\nWrote a total %d samples to file \"%s\"", written, output_file);

}


int calculate_clip_time(timing_pair * buffer, int size){
  int step = size / AVG_SAMPLE_SIZE;
  int low = buffer[0].time;
  int i;

  for(i = 0; i < size; i += step){

    if( buffer[i].time < low)
      low = buffer[i].time;
  }

  printf("\nLow time = %d, clipping at %d", low, low * CLIP_RATIO);
  return low * CLIP_RATIO;
}

int bound(int num){
  int bound = 1;
  int temp = num;
  while(temp = temp >> 1)
    bound++;
  
  return bound;
}


void re_key(key_data * key, char * filename)
{

#ifdef DECRYPT_MODE
    read_decrypt_key(key, filename);
    decrypt(zero, key->encrypted_zero, key);
#else    
    read_encrypt_key(key, filename);
    encrypt(zero, key->encrypted_zero, key);
#endif

}

int main(int argc,char **argv)
{  
  key_data key;

  char * in_file = 0;
  char * out_file = 0;

  int inc = 0;
  int num_trials = 1;

  if (!argv[1] || !argv[2]){
    printf("\nusage: aes_attack key_file/-random data_inc\
    [num_trials]/[-o output file]/[-i input file]");
    return -1;
  }
  srandom(time(0));

  USE_RANDOM_KEY = (argv[1][0] == '-' && argv[1][1] == 'r');


  if(argv[2]){
    inc = atoi(argv[2]);
    if(inc <= 0){
      printf("Can't use attack increment \"%s\"", argv[3]);
      return 101;
    }
    inc = 1 << inc;
  }

  if(argv[3]){
    if(argv[3][0] == '-')
      {
	if(argv[3][1] == 'o')
	  out_file = argv[4];

	else if(argv[3][1] == 'i')
	  in_file = argv[4];
      }

    else{
      num_trials = atoi(argv[3]);
       if(num_trials <= 0){
         printf("Can't use \"%s\" for number of trials", argv[4]);
         return 101;
       }
    }
  }

  printf("\nUsing algorithm \"%s\"", alg_name());
  if(USE_RANDOM_KEY)
    printf("\nAttacking random key(s)");
  else
    printf("\nAttacking key \"%s\"", argv[1]);

  printf("\nStudy increment: %d", inc);

  if(num_trials != 1)
    printf("\nNumber of trials: %d", num_trials);

  else if(out_file)
    printf("\nOutputting to file: %s", out_file);
  else if(in_file)
    printf("\nReading from file: %s", in_file);

#ifdef NONE_AES
  printf("\nAttacking NONE_AES_CORE implementation");
#elif defined(SMALL_AES)
  printf("\nAttacking SMALL_AES_CORE implementation");
#else
  printf("\nAttacking traditional AES_CORE implementation");
#endif

#ifdef DECRYPT_MODE
  printf("\nDECRYPT MODE");
#else
  printf("\nENCRYPT MODE");
#endif

  cache_evict_init();

  int * results = malloc(num_trials * sizeof(int));

  timing_pair * buffer = malloc(BUF_SIZE * sizeof(timing_pair));
  timing_data * data = malloc(sizeof(timing_data));
  FILE * in;
  if(!USE_RANDOM_KEY)
    re_key(&key, argv[1]);

  fflush(stdout);

  if(out_file){
    output_timings(out_file, buffer, inc, &key);
    return 1;
  }

  if(in_file){
    char open_type = 'r';
    in = fopen(in_file, &open_type);

    if(in == NULL){
      printf("\nCould not open file: %s", in_file);
      return -1;
    }
  }


  int round, i;
  for(round = 1; round <= num_trials; round++){

    printf("\nBeginning Attack #%d", round);
    
    init_data(data);

    if(USE_RANDOM_KEY)
      re_key(&key, "/dev/random");

    long long num_studies = 0;

    int clip_time = 0;

    int success = 0;



    long long max = MAX_STUDY;

    while(num_studies < max && !success){

      int offset = num_studies % BUF_SIZE;
      if(inc > BUF_SIZE){
	int read = 0;
	int num_read = BUF_SIZE;
	while(read < inc){
	  generate_samples(buffer, &key);     	
	clip_time = calculate_clip_time(buffer, num_read); 

	for(i = 0; i < BUF_SIZE && read < inc; i++){
	  if(buffer[offset + i].time < clip_time)
	    record_timing(data, &buffer[offset + i]);
	  
	  read++;
	}
	}
      } else{ 
	if(offset == 0){

	int num_read = BUF_SIZE;

	if(!in_file)
	  generate_samples(buffer, &key);
	else{
	  num_read = fread(buffer, sizeof(timing_pair), BUF_SIZE,in);
	  if(num_read < BUF_SIZE)
	    max = num_studies + num_read;

	  printf("\nRead in %d samples ", num_read);
	}
	clip_time = calculate_clip_time(buffer, num_read);
      }


      for(i = 0; i < inc; i++)
	if(buffer[offset + i].time < clip_time)
	  record_timing(data, &buffer[offset + i]);
      }
      num_studies += inc;
		       

      if(check_data(data, &key)){
	printf("\nKey recovered after studying %d samples (< 2^%d)\n", 
	       num_studies, bound(num_studies));

	success = 1;
      }
      else
	printf("\nNo success after studying %d samples",
	     num_studies);
    }
    if(!success)
    printf("Attack failed after %d encryptions", num_studies);

    else{

      int j = round - 1;

      while(j > 0 && results[j - 1] > num_studies){
	results[j] = results[j - 1];
	j--;
      }

      results[j] = num_studies;


      printf("\nResults: ");
      
      int total = 0;

      for(j = 0; j < round; j++){
	printf("  %d ", results[j]);
	total += results[j];
      }

      printf("\nMin: %d", results[0]);
      printf("\nMax: %d", results[round - 1]);
      
      printf("\nMed: %d", results[round / 2]);
      printf("\nMean: %.2f", ((double) total) / round);

    }
  }

}
