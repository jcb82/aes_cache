#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include "encrypt.h"
#include "key_revert.h"
#include "cache_evict.h"
#include "constants.h"
#include "aes_attack.h"


#ifndef ALG_HEADER

#define ALG_HEADER

#ifdef XHS_ATTACK

typedef struct{
  long long total_num_timings;
  double total_time;

  long time[KEY_LENGTH][KEY_LENGTH][256][256];
  int num_timings[KEY_LENGTH][KEY_LENGTH][256][256];  
  double cost[KEY_LENGTH][KEY_LENGTH][256][256];
  unsigned char ranks[KEY_LENGTH][KEY_LENGTH][256][256];
} timing_data;


#elif defined HS_ATTACK
typedef struct{
  long long total_num_timings;
  double total_time;

  double time[KEY_LENGTH][KEY_LENGTH][256];
  double time_squared[KEY_LENGTH][KEY_LENGTH][256];
  long long num_timings[KEY_LENGTH][KEY_LENGTH][256];
  double mean[KEY_LENGTH][KEY_LENGTH][256];
  double variance[KEY_LENGTH][KEY_LENGTH][256];
} timing_data;

#elif defined W_ATTACK

#define NUM_TABLES 4

// 4 choose 2
#define NUM_DIFF_SETS 6

//2 ^ (8 - UNK_BITS)
#define NUM_DIFFS 32

typedef struct{

  long long total_num_timings;
  double total_time;  

  double time[NUM_TABLES][NUM_DIFF_SETS][NUM_DIFFS];
  double time_squared[NUM_TABLES][NUM_DIFF_SETS][NUM_DIFFS];
  long long num_timings[NUM_TABLES][NUM_DIFF_SETS][NUM_DIFFS];
  double mean[NUM_TABLES][NUM_DIFF_SETS][NUM_DIFFS];
  double variance[NUM_TABLES][NUM_DIFF_SETS][NUM_DIFFS];
} timing_data;
#endif


const char * alg_name();
int timing_sample(key_data * key, timing_pair * data);

void init_data(timing_data * data);
void record_timing(timing_data * data, timing_pair * pair);
int check_data(timing_data * data, key_data * key);
void cache_evict();

#endif /*ALG_HEADER SEEN */


