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

#define VOTE_LIMIT 16

static const unsigned int S_box[256] = {
    0x63636363U, 0x7c7c7c7cU, 0x77777777U, 0x7b7b7b7bU,
    0xf2f2f2f2U, 0x6b6b6b6bU, 0x6f6f6f6fU, 0xc5c5c5c5U,
    0x30303030U, 0x01010101U, 0x67676767U, 0x2b2b2b2bU,
    0xfefefefeU, 0xd7d7d7d7U, 0xababababU, 0x76767676U,
    0xcacacacaU, 0x82828282U, 0xc9c9c9c9U, 0x7d7d7d7dU,
    0xfafafafaU, 0x59595959U, 0x47474747U, 0xf0f0f0f0U,
    0xadadadadU, 0xd4d4d4d4U, 0xa2a2a2a2U, 0xafafafafU,
    0x9c9c9c9cU, 0xa4a4a4a4U, 0x72727272U, 0xc0c0c0c0U,
    0xb7b7b7b7U, 0xfdfdfdfdU, 0x93939393U, 0x26262626U,
    0x36363636U, 0x3f3f3f3fU, 0xf7f7f7f7U, 0xccccccccU,
    0x34343434U, 0xa5a5a5a5U, 0xe5e5e5e5U, 0xf1f1f1f1U,
    0x71717171U, 0xd8d8d8d8U, 0x31313131U, 0x15151515U,
    0x04040404U, 0xc7c7c7c7U, 0x23232323U, 0xc3c3c3c3U,
    0x18181818U, 0x96969696U, 0x05050505U, 0x9a9a9a9aU,
    0x07070707U, 0x12121212U, 0x80808080U, 0xe2e2e2e2U,
    0xebebebebU, 0x27272727U, 0xb2b2b2b2U, 0x75757575U,
    0x09090909U, 0x83838383U, 0x2c2c2c2cU, 0x1a1a1a1aU,
    0x1b1b1b1bU, 0x6e6e6e6eU, 0x5a5a5a5aU, 0xa0a0a0a0U,
    0x52525252U, 0x3b3b3b3bU, 0xd6d6d6d6U, 0xb3b3b3b3U,
    0x29292929U, 0xe3e3e3e3U, 0x2f2f2f2fU, 0x84848484U,
    0x53535353U, 0xd1d1d1d1U, 0x00000000U, 0xededededU,
    0x20202020U, 0xfcfcfcfcU, 0xb1b1b1b1U, 0x5b5b5b5bU,
    0x6a6a6a6aU, 0xcbcbcbcbU, 0xbebebebeU, 0x39393939U,
    0x4a4a4a4aU, 0x4c4c4c4cU, 0x58585858U, 0xcfcfcfcfU,
    0xd0d0d0d0U, 0xefefefefU, 0xaaaaaaaaU, 0xfbfbfbfbU,
    0x43434343U, 0x4d4d4d4dU, 0x33333333U, 0x85858585U,
    0x45454545U, 0xf9f9f9f9U, 0x02020202U, 0x7f7f7f7fU,
    0x50505050U, 0x3c3c3c3cU, 0x9f9f9f9fU, 0xa8a8a8a8U,
    0x51515151U, 0xa3a3a3a3U, 0x40404040U, 0x8f8f8f8fU,
    0x92929292U, 0x9d9d9d9dU, 0x38383838U, 0xf5f5f5f5U,
    0xbcbcbcbcU, 0xb6b6b6b6U, 0xdadadadaU, 0x21212121U,
    0x10101010U, 0xffffffffU, 0xf3f3f3f3U, 0xd2d2d2d2U,
    0xcdcdcdcdU, 0x0c0c0c0cU, 0x13131313U, 0xececececU,
    0x5f5f5f5fU, 0x97979797U, 0x44444444U, 0x17171717U,
    0xc4c4c4c4U, 0xa7a7a7a7U, 0x7e7e7e7eU, 0x3d3d3d3dU,
    0x64646464U, 0x5d5d5d5dU, 0x19191919U, 0x73737373U,
    0x60606060U, 0x81818181U, 0x4f4f4f4fU, 0xdcdcdcdcU,
    0x22222222U, 0x2a2a2a2aU, 0x90909090U, 0x88888888U,
    0x46464646U, 0xeeeeeeeeU, 0xb8b8b8b8U, 0x14141414U,
    0xdedededeU, 0x5e5e5e5eU, 0x0b0b0b0bU, 0xdbdbdbdbU,
    0xe0e0e0e0U, 0x32323232U, 0x3a3a3a3aU, 0x0a0a0a0aU,
    0x49494949U, 0x06060606U, 0x24242424U, 0x5c5c5c5cU,
    0xc2c2c2c2U, 0xd3d3d3d3U, 0xacacacacU, 0x62626262U,
    0x91919191U, 0x95959595U, 0xe4e4e4e4U, 0x79797979U,
    0xe7e7e7e7U, 0xc8c8c8c8U, 0x37373737U, 0x6d6d6d6dU,
    0x8d8d8d8dU, 0xd5d5d5d5U, 0x4e4e4e4eU, 0xa9a9a9a9U,
    0x6c6c6c6cU, 0x56565656U, 0xf4f4f4f4U, 0xeaeaeaeaU,
    0x65656565U, 0x7a7a7a7aU, 0xaeaeaeaeU, 0x08080808U,
    0xbabababaU, 0x78787878U, 0x25252525U, 0x2e2e2e2eU,
    0x1c1c1c1cU, 0xa6a6a6a6U, 0xb4b4b4b4U, 0xc6c6c6c6U,
    0xe8e8e8e8U, 0xddddddddU, 0x74747474U, 0x1f1f1f1fU,
    0x4b4b4b4bU, 0xbdbdbdbdU, 0x8b8b8b8bU, 0x8a8a8a8aU,
    0x70707070U, 0x3e3e3e3eU, 0xb5b5b5b5U, 0x66666666U,
    0x48484848U, 0x03030303U, 0xf6f6f6f6U, 0x0e0e0e0eU,
    0x61616161U, 0x35353535U, 0x57575757U, 0xb9b9b9b9U,
    0x86868686U, 0xc1c1c1c1U, 0x1d1d1d1dU, 0x9e9e9e9eU,
    0xe1e1e1e1U, 0xf8f8f8f8U, 0x98989898U, 0x11111111U,
    0x69696969U, 0xd9d9d9d9U, 0x8e8e8e8eU, 0x94949494U,
    0x9b9b9b9bU, 0x1e1e1e1eU, 0x87878787U, 0xe9e9e9e9U,
    0xcecececeU, 0x55555555U, 0x28282828U, 0xdfdfdfdfU,
    0x8c8c8c8cU, 0xa1a1a1a1U, 0x89898989U, 0x0d0d0d0dU,
    0xbfbfbfbfU, 0xe6e6e6e6U, 0x42424242U, 0x68686868U,
    0x41414141U, 0x99999999U, 0x2d2d2d2dU, 0x0f0f0f0fU,
    0xb0b0b0b0U, 0x54545454U, 0xbbbbbbbbU, 0x16161616U,
};


static const unsigned int S_Inv[256] = {
    0x52525252U, 0x09090909U, 0x6a6a6a6aU, 0xd5d5d5d5U,
    0x30303030U, 0x36363636U, 0xa5a5a5a5U, 0x38383838U,
    0xbfbfbfbfU, 0x40404040U, 0xa3a3a3a3U, 0x9e9e9e9eU,
    0x81818181U, 0xf3f3f3f3U, 0xd7d7d7d7U, 0xfbfbfbfbU,
    0x7c7c7c7cU, 0xe3e3e3e3U, 0x39393939U, 0x82828282U,
    0x9b9b9b9bU, 0x2f2f2f2fU, 0xffffffffU, 0x87878787U,
    0x34343434U, 0x8e8e8e8eU, 0x43434343U, 0x44444444U,
    0xc4c4c4c4U, 0xdedededeU, 0xe9e9e9e9U, 0xcbcbcbcbU,
    0x54545454U, 0x7b7b7b7bU, 0x94949494U, 0x32323232U,
    0xa6a6a6a6U, 0xc2c2c2c2U, 0x23232323U, 0x3d3d3d3dU,
    0xeeeeeeeeU, 0x4c4c4c4cU, 0x95959595U, 0x0b0b0b0bU,
    0x42424242U, 0xfafafafaU, 0xc3c3c3c3U, 0x4e4e4e4eU,
    0x08080808U, 0x2e2e2e2eU, 0xa1a1a1a1U, 0x66666666U,
    0x28282828U, 0xd9d9d9d9U, 0x24242424U, 0xb2b2b2b2U,
    0x76767676U, 0x5b5b5b5bU, 0xa2a2a2a2U, 0x49494949U,
    0x6d6d6d6dU, 0x8b8b8b8bU, 0xd1d1d1d1U, 0x25252525U,
    0x72727272U, 0xf8f8f8f8U, 0xf6f6f6f6U, 0x64646464U,
    0x86868686U, 0x68686868U, 0x98989898U, 0x16161616U,
    0xd4d4d4d4U, 0xa4a4a4a4U, 0x5c5c5c5cU, 0xccccccccU,
    0x5d5d5d5dU, 0x65656565U, 0xb6b6b6b6U, 0x92929292U,
    0x6c6c6c6cU, 0x70707070U, 0x48484848U, 0x50505050U,
    0xfdfdfdfdU, 0xededededU, 0xb9b9b9b9U, 0xdadadadaU,
    0x5e5e5e5eU, 0x15151515U, 0x46464646U, 0x57575757U,
    0xa7a7a7a7U, 0x8d8d8d8dU, 0x9d9d9d9dU, 0x84848484U,
    0x90909090U, 0xd8d8d8d8U, 0xababababU, 0x00000000U,
    0x8c8c8c8cU, 0xbcbcbcbcU, 0xd3d3d3d3U, 0x0a0a0a0aU,
    0xf7f7f7f7U, 0xe4e4e4e4U, 0x58585858U, 0x05050505U,
    0xb8b8b8b8U, 0xb3b3b3b3U, 0x45454545U, 0x06060606U,
    0xd0d0d0d0U, 0x2c2c2c2cU, 0x1e1e1e1eU, 0x8f8f8f8fU,
    0xcacacacaU, 0x3f3f3f3fU, 0x0f0f0f0fU, 0x02020202U,
    0xc1c1c1c1U, 0xafafafafU, 0xbdbdbdbdU, 0x03030303U,
    0x01010101U, 0x13131313U, 0x8a8a8a8aU, 0x6b6b6b6bU,
    0x3a3a3a3aU, 0x91919191U, 0x11111111U, 0x41414141U,
    0x4f4f4f4fU, 0x67676767U, 0xdcdcdcdcU, 0xeaeaeaeaU,
    0x97979797U, 0xf2f2f2f2U, 0xcfcfcfcfU, 0xcecececeU,
    0xf0f0f0f0U, 0xb4b4b4b4U, 0xe6e6e6e6U, 0x73737373U,
    0x96969696U, 0xacacacacU, 0x74747474U, 0x22222222U,
    0xe7e7e7e7U, 0xadadadadU, 0x35353535U, 0x85858585U,
    0xe2e2e2e2U, 0xf9f9f9f9U, 0x37373737U, 0xe8e8e8e8U,
    0x1c1c1c1cU, 0x75757575U, 0xdfdfdfdfU, 0x6e6e6e6eU,
    0x47474747U, 0xf1f1f1f1U, 0x1a1a1a1aU, 0x71717171U,
    0x1d1d1d1dU, 0x29292929U, 0xc5c5c5c5U, 0x89898989U,
    0x6f6f6f6fU, 0xb7b7b7b7U, 0x62626262U, 0x0e0e0e0eU,
    0xaaaaaaaaU, 0x18181818U, 0xbebebebeU, 0x1b1b1b1bU,
    0xfcfcfcfcU, 0x56565656U, 0x3e3e3e3eU, 0x4b4b4b4bU,
    0xc6c6c6c6U, 0xd2d2d2d2U, 0x79797979U, 0x20202020U,
    0x9a9a9a9aU, 0xdbdbdbdbU, 0xc0c0c0c0U, 0xfefefefeU,
    0x78787878U, 0xcdcdcdcdU, 0x5a5a5a5aU, 0xf4f4f4f4U,
    0x1f1f1f1fU, 0xddddddddU, 0xa8a8a8a8U, 0x33333333U,
    0x88888888U, 0x07070707U, 0xc7c7c7c7U, 0x31313131U,
    0xb1b1b1b1U, 0x12121212U, 0x10101010U, 0x59595959U,
    0x27272727U, 0x80808080U, 0xececececU, 0x5f5f5f5fU,
    0x60606060U, 0x51515151U, 0x7f7f7f7fU, 0xa9a9a9a9U,
    0x19191919U, 0xb5b5b5b5U, 0x4a4a4a4aU, 0x0d0d0d0dU,
    0x2d2d2d2dU, 0xe5e5e5e5U, 0x7a7a7a7aU, 0x9f9f9f9fU,
    0x93939393U, 0xc9c9c9c9U, 0x9c9c9c9cU, 0xefefefefU,
    0xa0a0a0a0U, 0xe0e0e0e0U, 0x3b3b3b3bU, 0x4d4d4d4dU,
    0xaeaeaeaeU, 0x2a2a2a2aU, 0xf5f5f5f5U, 0xb0b0b0b0U,
    0xc8c8c8c8U, 0xebebebebU, 0xbbbbbbbbU, 0x3c3c3c3cU,
    0x83838383U, 0x53535353U, 0x99999999U, 0x61616161U,
    0x17171717U, 0x2b2b2b2bU, 0x04040404U, 0x7e7e7e7eU,
    0xbabababaU, 0x77777777U, 0xd6d6d6d6U, 0x26262626U,
    0xe1e1e1e1U, 0x69696969U, 0x14141414U, 0x63636363U,
    0x55555555U, 0x21212121U, 0x0c0c0c0cU, 0x7d7d7d7dU,
};


typedef struct{
    unsigned char c;
    double v;
} char_double_pair;


/*
 * Initialize timing data values to zeroes.
 */
void init_data(timing_data * data)
{

   data->total_num_timings = 0; 
   data->total_time = 0; 

   int i, j, k, m;

   for(i = 0; i < KEY_LENGTH; i++)
     for(j = 0; j < KEY_LENGTH; ++j)
       for(k = 0; k < 256; ++k)      
	 for(m = 0; m < 256; ++m){
	 data->time[i][j][k][m] = 0; 
	 data->num_timings[i][j][k][m] = 0; 
       }
}

int cdp_compare( const void *arg1, const void *arg2 )
{
    if(((char_double_pair *)arg1)->v > ((char_double_pair *)arg2)->v)
	return 1;
    else if(((char_double_pair *)arg1)->v < ((char_double_pair *)arg2)->v)
	return -1;
    else
	return 0;   
}

/*
 * Check a key guess against the known encryption of zero to see if it is
 * correct.
 */
int check_key(unsigned char * key_guess, timing_data * data, key_data * key)
{

  int j;
  key_data candidate_key;
  unsigned char ciphertext[KEY_LENGTH];

#ifdef DECRYPT_MODE
  for(j = 0; j < KEY_LENGTH; j++)
    candidate_key.key_byte[j] = key_guess[j];
#else
  revert_key(key_guess, candidate_key.key_byte);
#endif

  AES_set_encrypt_key(candidate_key.key_byte,128, &candidate_key.expanded);
  encrypt(zero, ciphertext, &candidate_key);
      
  int foundMismatch = 0;

  for(j = 0; j < 16; j++)
    if(ciphertext[j] != key->encrypted_zero[j])
      foundMismatch++;

  if(!foundMismatch)
    {

      printf("\n\n######################");
      printf("\nRECOVERED AES KEY:\n");

      for(j = 0; j < KEY_LENGTH; j++)
	printf("%02x ", candidate_key.key_byte[j]);
	  
      printf("\n######################\n");
      return 1;
    }

  return 0;
}



void compute_cost(timing_data* data, key_data * key){
  
  int i, j, u, v;
  short c, d, c_prime;

#ifdef DECRYPT_MODE  
  unsigned char * opb = (unsigned char *) ( key->expanded.rd_key);
#else
    unsigned char * opb = (unsigned char *) ( key->expanded.rd_key + 40);
#endif

  double taverage = data->total_time/ data->total_num_timings;
  double diff_time[256][256];

  for(i = 0; i < KEY_LENGTH - 1; i++){
    for(j = i + 1; j < KEY_LENGTH; j++){
      if(i % 4 == j % 4){	  
      double low_time = taverage;
      int low_u, low_v;

      for(u = 0; u <= 255; u++)
	for(v = 0; v <= 255; v++){
	  diff_time[u][v] = 0;

	  long long t_total = 0;
	  int num_timings = 0;

	  for(c = 0; c < 256; c++){

#ifdef DECRYPT_MODE
	    int lookup_start = S_box[(u ^ c) & 0xff] & TABLE_MASK;
#else
	    int lookup_start = S_Inv[(u ^ c) & 0xff] & TABLE_MASK;
#endif
	    for(d = 0; d < DELTA; d++){

#ifdef DECRYPT_MODE
	      c_prime = (S_Inv[(lookup_start ^ d)& 0xff] & 0xff) ^ v;
#else 
	      c_prime = (S_box[(lookup_start ^ d)& 0xff] & 0xff) ^ v;
#endif

	      t_total +=data->time[i][j][c][c_prime];
	      num_timings +=data->num_timings[i][j][c][c_prime]; 
	    }
	  }
	  
	  diff_time[u][v] = ((double) t_total ) / num_timings;
	  data->cost[i][j][u][v] = diff_time[u][v];
	  if(diff_time[u][v] < low_time)
	    {
	      low_u = u;
	      low_v = v;
	      low_time = diff_time[u][v];
	    }
	  
/* 	  if(i == 0 && j == 1) */
/* 	    printf("\n %d, %d, %.6f", u, v, diff_time[u][v]); */

	}

      double true_value = diff_time[opb[i ^ 3]][opb[j^3]];

      int rank = 0;
      for(u = 0; u <= 255; u++)
	for(v = 0; v <= 255; v++)
	  if(diff_time[u][v] <= true_value)
	    rank++;

      printf("  [%d, %d] ?=  %02x, %02x, ", i, j, low_u, low_v);
      printf(" %0.6f ", low_time - taverage);
      printf("(T = %02x/%02x, %d)", opb[i ^ 3], opb[j^3], rank);

    }
  }
  }
}

void compute_rank_table(timing_data * data, key_data * key){
  int i, j, u, v;


  #ifdef DECRYPT_MODE
unsigned char * opb = (unsigned char *) ( key->expanded.rd_key);
  #else
  unsigned char * opb = (unsigned char *) ( key->expanded.rd_key + 40);
  #endif


  for(i = 0; i < KEY_LENGTH; i++)
	for(j = i+1; j < KEY_LENGTH; j++){
	  if(i % 4 == j % 4){

		for(u= 0; u < 256; u++){
		  char_double_pair temp_row[256];
		  for(v = 0; v < 256; v++){

		    temp_row[v].c = v;
		    temp_row[v].v = data->cost[i][j][u][v];


		  }
		  qsort(temp_row, 256, sizeof(char_double_pair), cdp_compare);
		  for(v = 0; v < 256; v++)
		    data->ranks[i][j][u][temp_row[v].c] = v;

		  for(v = 0; v < 256; v++){
		    temp_row[v].c = v;
		    temp_row[v].v = data->cost[i][j][v][u];
		  }
		  qsort(temp_row, 256, sizeof(char_double_pair), cdp_compare);
		  for(v = 0; v < 256; v++)
		    data->ranks[j][i][u][temp_row[v].c] = v;

		}
	  }
	}

    // print statistics for the true key
    printf("Row ranking:\n");
    for(i = 0; i < KEY_LENGTH; i++){
	printf("%2d:", i);
	for(j = 0; j < KEY_LENGTH; j++)
	    if(i == j || i % 4 != j % 4)
	      printf("    ");
	    else
	      printf("%3d ", data->ranks[i][j][opb[i ^ 3]][opb[j^3]]);
	printf("\n");
    }


    printf("Column ranking:\n");
    for(i = 0; i < KEY_LENGTH; i++){
	printf("%2d:", i);
	for(j = 0; j < KEY_LENGTH; j++)
	    if(i == j || i % 4 != j % 4)
	      printf("    ");
	    else	
	      printf("%3d ", data->ranks[j][i][opb[j ^ 3]][opb[i^3]]);
	printf("\n");
    }
}


/*
 *Perform a binary search for the threshold x, such that <= count elements are less
 *x
 */
double find_threshold(int count, double t[256][256], int i_lo , int i_hi, int j_lo, int j_hi){
    
  int i, j;
  double min = 1E6, max = 0;
    for(i = i_lo; i <= i_hi; i++) for(j = j_lo; j <= j_hi; j++){
	if(t[i][j] < min)
	    min = t[i][j];
	if(t[i][j] > max)
	    max = t[i][j];
    }

    double l = min - 1;
    double r = max + 1;

    while(l < r - 1E-5){
	double x = (l+r) / 2;
	int d = count_below(x, t, i_lo, i_hi, j_lo, j_hi);
	if(d == count)
	    return x;
	if(d < count)
	    l = x;
	else
	    r = x;
    }
    printf("Problem in \"Find Threshold\"\n");
    return l;
}

/*
 * Count the number of elements below x in the matrix
 */
int count_below(double x, double t[256][256], int i_lo, int i_hi, int j_lo, int j_hi){
  int i, j, sum = 0;
    for(i = i_lo; i <= i_hi; i++) 
      for(j = j_lo; j <= j_hi; j++)
	if(t[i][j] < x)
	    sum++;
    return sum;
}

/*
 *Find the maximal element in the array
 */
int find_max(int vec[], int len){
    int max = vec[0];
    int i, pos = 0;
    for(i = 1; i < len; i++)
	if(vec[i] > max){
	    max = vec[i];
	    pos = i;
	}
    return pos;
}

/*
 * Make an initial guess about the key
 */
void first_guess(timing_data * data, unsigned char * key_guess){
    
  int i, j, u, v;
  int votes[KEY_LENGTH][256];
    memset(votes, 0, sizeof(votes));

    for(i = 0; i < KEY_LENGTH; i++) 
      for(j = i + 1; j < KEY_LENGTH; j++){
	if( i % 4 == j % 4){
	double x = find_threshold(VOTE_LIMIT, data->cost[i][j], 0, 255, 0, 255);
 	for(u = 0; u < 256; u++) 	
	    for(v = 0; v < 256; v++)
	      if(data->cost[i][j][u][v] < x){
		    votes[i][u]++;
		    votes[j][v]++;
		}
	}	    
    }

    for(i = 0; i < KEY_LENGTH; i++){
	u = find_max(votes[i], 256);
	key_guess[i] = u;
    }
}

int score_byte_guess(timing_data * data, unsigned char *  key_guess, int j){
  int i, score = 0;
    for(i = 0; i < KEY_LENGTH; i++) if(i != j && i % 4 == j % 4){
	int d = data->ranks[i][j][key_guess[i]][key_guess[j]];
	if(d < VOTE_LIMIT)
	    score += (VOTE_LIMIT - d);

	d = data->ranks[j][i][key_guess[j]][key_guess[i]];
	if(d < VOTE_LIMIT)
	    score += (VOTE_LIMIT - d);
    }
    return score;
}

int score_key_guess(timing_data * data, unsigned char *  key_guess){
  int i, score = 0;
    for(i = 0; i < KEY_LENGTH; i++)
      score += score_byte_guess(data, key_guess, i);
    return score;
}

void walk(timing_data * data, unsigned char *  key_guess){
  int j, progress = 1;
    while(progress){
	progress = 0;
	int minp = 0;
	int minc = 1000;
	for(j = 0; j < 16; j++){	    // find the key byte that fits the worst
	  int x = score_byte_guess(data, key_guess, j);
	    if(x < minc){
		minc = x;
		minp = j;
	    }
	}

	int maxv = key_guess[minp];
	int maxc = score_byte_guess(data, key_guess, minp);
	for(j = 0; j < 256; j++){	   // change its value that maximizes the overall goodness of fit
	    key_guess[minp] = j;
	    int x =score_byte_guess(data, key_guess, minp);
	    if(x > maxc){
		maxc = x;
		maxv = j;
		progress = 1;
	    }
	}
	
        key_guess[minp] = maxv;
    }
}


int check_data(timing_data* data, key_data * key){
    unsigned char key_guess[KEY_LENGTH];
    int i;

    compute_cost(data, key);
    compute_rank_table(data, key);

    first_guess(data, key_guess);
    printf("\nInitial guess: ");
    for(i = 0; i < KEY_LENGTH; i++)
      printf(" %02x ", key_guess[i]);

    walk(data, key_guess);
    printf("Walk         : "); 

    if(check_key(key_guess, data, key) )
       return 1;

    for(i = 0; i < KEY_LENGTH; i++)
      printf(" %02x ", key_guess[i]);

    if(check_key(key_guess, data, key) )
       return 1;

    return 0;
}



/*
 * Record the timing data for one trial. This gets recorded in the
 * table in many places. 
 */
void record_timing(timing_data * data, timing_pair * t)
{
  int i, j;

    data->total_num_timings += 1; 
    data->total_time  += t->time; 

    for(i = 0; i < 16; i++)
      for(j = i + 1; j < 16; ++j){
	if(i % 4 == j % 4){
	  data->time[i][j][t->value[i]][t->value[j]] +=t->time;
	  data->num_timings[i][j][t->value[i]][t->value[j]]++;
	}
      }
}



void cache_evict()
{
#ifdef NONE_AES
  w_cache_evict();
#elif defined(DECRYPT_MODE)
  dhs_cache_evict();
  #else
  hs_cache_evict();
  #endif
}
