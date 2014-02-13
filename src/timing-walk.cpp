#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <time.h>
#include <memory.h>

unsigned long seed[2];
unsigned long int my_rand(){
// prng recommeded by George Marsaglia (of DIEHARD fame)
   seed[0] = 36969 * (seed[0] & 0xFFFF) + (seed[0] >> 16);
   seed[1] = 18000 * (seed[1] & 0xFFFF) + (seed[1] >> 16);

   return (seed[0] << 16) + (seed[1] & 0xFFFF);
}

unsigned long my_srand(unsigned long int _seed){
	seed[0] = _seed;
	seed[1] = 2 * _seed * _seed - _seed; // Rivest's permutation polynomial 
	for (int i = 0; i < 4; i++) my_rand();
	return my_rand();
}


const int KEY_LENGTH = 16;

//Look at a maximum of 2^28 timings
#define TOTAL_READ (1<<12)
#define BUF_SIZE (1<<12)

#define PRINT_FREQ 0x20000
#define MAX_PRINTS   0x400

#define MIN_AGR 2
#define BRUTE_FORCE_LIM 3

#define BELIEF_PROP_LIMIT 10
#define RANDOM_WALK_LIMIT 10

#define BELIEF_PROP_SUCCESS 1

#define AVG_SAMPLE_SIZE 0x100

#define CLIP_RATIO 2.0

long long belief_exit = 0;

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

typedef unsigned char key_data[16];

typedef struct {
  int time;
  unsigned char ciphertext[KEY_LENGTH];
} timing_pair;


typedef struct{
  long long total_num_timings;
  double total_time;

  long time[KEY_LENGTH][KEY_LENGTH][256][256];
  //double time_squared[KEY_LENGTH][KEY_LENGTH][256][256];
  int num_timings[KEY_LENGTH][KEY_LENGTH][256][256];  
  double guess_prob[KEY_LENGTH][KEY_LENGTH][256][256];
  // double mean[KEY_LENGTH][KEY_LENGTH][256];
  //  double variance[KEY_LENGTH][KEY_LENGTH][256];

  unsigned char encrypted_zero[16];
} timing_data;

typedef double large_table[256][256];
typedef unsigned char large_char_table[256][256];

typedef large_char_table *rank_array[KEY_LENGTH][KEY_LENGTH];
typedef large_table *cost_table[KEY_LENGTH][KEY_LENGTH];

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


/*
 * Record the timing data for one trial. This gets recorded in the
 * table in many places. 
 */
void record_timing(timing_data * data, timing_pair * t, int cutoff)
{

  if(t->time > cutoff)
    return;

  int i, j;
/*
    if(t->ciphertext[0] == 0 &&
       t->ciphertext[1] == 0)
            {

	      printf("\n");

	for(j = 0; j < KEY_LENGTH; j++)
	  printf("%02x ", t->ciphertext[j]);
	
	printf(" = %d", t->time);
      }
*/
    data->total_num_timings += 1; 
    data->total_time  += t->time; 

    for(i = 0; i < 16; i++)
      for(j = i + 1; j < 16; ++j){
	data->time[i][j][t->ciphertext[i]][t->ciphertext[j]] +=t->time;
	data->num_timings[i][j][t->ciphertext[i]][t->ciphertext[j]]++;

/* 	printf("\n%d, %d", */
/* 	data->time[i][j][t->ciphertext[i]][t->ciphertext[j]],  */
/* 	       data->num_timings[i][j][t->ciphertext[i]][t->ciphertext[j]]); */
      }
}

void skip_data(FILE *in, int count){
  int total_read = 0;
  timing_pair * buffer = (timing_pair *) malloc(BUF_SIZE * sizeof(timing_pair));

  for(;;){
      int num_read = fread(buffer, sizeof(timing_pair), BUF_SIZE, in);

      if(num_read == 0)
	break;

      total_read += num_read;
      if(total_read > count)
	  break;
  }

}

void read_data(timing_data * data, char * filename)
{
  int i, j;

  timing_pair * buffer = (timing_pair *) malloc(BUF_SIZE * sizeof(timing_pair));

  FILE * in = fopen(filename, "rb");

  if(in == NULL){
    printf("\nCould not open file: %s", filename);
    return;
  }

  int low = 0; 
  int cutoff_time;
  int step;
  int total_read = 0;

  skip_data(in, (1<<17));

  while(1){
      int num_read = fread(buffer, sizeof(timing_pair), BUF_SIZE, in);

      if(num_read == 0)
	break;

      total_read += num_read;
      if(total_read > TOTAL_READ)
	  break;

      step = BUF_SIZE / AVG_SAMPLE_SIZE;

      
      low = buffer[0].time;

      for(i = 0; i < BUF_SIZE; i += step){
//	printf(", %d",  buffer[i].time);
	if( buffer[i].time < low)
	  low = buffer[i].time;

      }

      cutoff_time = CLIP_RATIO * low;
      

      printf("Low time = %d, clipping at %d\n", low, cutoff_time);


      for(i = 0; i < num_read; i++)
	record_timing(data, buffer + i, cutoff_time);

      printf("Read in %d timings\n", num_read);

  }
   if(fclose(in) != 0)
     printf("Error occured...");

/*    free(buffer); */

   printf("Data read in from file \"%s\"\n", filename); 
}

void compute_cost(int i, int j, timing_data* data, large_table t){
  //64-byte lines
   int TABLE_ASSOC = 16;
   int TABLE_MASK = 0xf0;

//32-byte lines
/*   int TABLE_ASSOC = 8; */
/*   int TABLE_MASK = 0xf8; */

    for(int u = 0; u < 256; u++) for(int v = 0; v < 256; v++){
	  t[u][v] = 0;

	  long long t_total = 0;
	  int num_timings = 0;

	  for(int c = 0; c < 256; c++){
	    int lookup_start = S_Inv[(u ^ c) & 0xff] & TABLE_MASK;
	    for(int d = 0; d < TABLE_ASSOC; d++){
	      short c_prime = (S_box[(lookup_start ^ d)& 0xff] & 0xff) ^ v;
	      t_total +=data->time[i][j][c][c_prime];
	       num_timings +=data->num_timings[i][j][c][c_prime]; 
	    }
	  }
	  
	  t[u][v] = ((double) t_total ) / num_timings;
    }
}


// count the number of elements in the table below x
int count_below(double x, large_table t,int i_lo, int i_hi, int j_lo, int j_hi){
    int sum = 0;
    for(int i = i_lo; i <= i_hi; i++) for(int j = j_lo; j <= j_hi; j++)
	if(t[i][j] < x)
	    sum++;
    return sum;
}

// binary search for the threshold x, such that <= count elements are less x
double find_threshold(int count, large_table t, int i_lo = 0, int i_hi = 255, int j_lo = 0, int j_hi = 255){
    double min = 1E6, max = 0;
    for(int i = i_lo; i <= i_hi; i++) for(int j = j_lo; j <= j_hi; j++){
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
    printf("Problem?\n");
    return l;
}

int find_max(int vec[], int len){
    int max = vec[0];
    int pos = 0;
    for(int i = 1; i < len; i++)
	if(vec[i] > max){
	    max = vec[i];
	    pos = i;
	}
    return pos;
}

typedef struct{
    unsigned char c;
    double v;
} pair_char_double;

typedef pair_char_double *ppair_char_double;

int compare( const void *arg1, const void *arg2 )
{
    if(((ppair_char_double)arg1)->v > ((ppair_char_double)arg2)->v)
	return 1;
    else if(((ppair_char_double)arg1)->v < ((ppair_char_double)arg2)->v)
	return -1;
    else
	return 0;   
}

void compute_row_ranks(large_table t, large_char_table rank12_row, large_char_table rank21_row){
    for(int i = 0; i < 256; i++){
	pair_char_double row12[256];
	for(int j = 0; j < 256; j++){
	    row12[j].c = j;
	    row12[j].v = t[i][j];
	}
	qsort(row12, 256, sizeof(pair_char_double), compare);
	for(int j = 0; j < 256; j++)
	    rank12_row[i][row12[j].c] = j;

    	pair_char_double row21[256];
	for(int j = 0; j < 256; j++){
	    row21[j].c = j;
	    row21[j].v = t[j][i];
	}
	qsort(row21, 256, sizeof(pair_char_double), compare);
	for(int j = 0; j < 256; j++)
	    rank21_row[i][row21[j].c] = j;
    }
}

int goodness(key_data key, int k, rank_array ranks){
    int r = 0;
    for(int i = 0; i < KEY_LENGTH; i++) if(i != k){
	int d = (*ranks[i][k])[key[i]][key[k]];
	if(d < 16)
	    r += (16 - d);

	d = (*ranks[k][i])[key[k]][key[i]];
	if(d < 16)
	    r += (16 - d);

    }
    return r;
}

int goodness(key_data key, rank_array ranks){
    int r = 0;
    for(int k = 0; k < KEY_LENGTH; k++)
	r += goodness(key, k, ranks);
    return r;
}

void print_key(key_data key, key_data truekey){
    int match = 0;
    for(int i = 0; i < KEY_LENGTH; i++){
	printf("%02x ", key[i]);
	if(key[i] == truekey[i])
	    match++;
    }
    printf("%d matched\n", match);
}

void walk(key_data key, rank_array ranks, key_data truekey){
    bool progress = true;
    while(progress){
	progress = false;
	int minp = 0;
	int minc = 1000;
	for(int j = 0; j < 16; j++){	    // find the key byte that fits the worst
	    int x = goodness(key, j, ranks);
	    if(x < minc){
		minc = x;
		minp = j;
	    }
	}

	int maxv = key[minp];
	int maxc = goodness(key, minp, ranks);
	for(int j = 0; j < 256; j++){	   // change its value that maximizes the overall goodness of fit
	    key[minp] = j;
	    int x = goodness(key, minp, ranks);
	    if(x > maxc){
		maxc = x;
		maxv = j;
		progress = true;
	    }
	}
	
        key[minp] = maxv;
        printf("cost = %3d ", goodness(key, ranks)); print_key(key, truekey);
    }
}

void first_guess(key_data key, cost_table cost){
    int votes[KEY_LENGTH][256];
    memset(votes, 0, sizeof(votes));

    for(int i = 0; i < KEY_LENGTH; i++) for(int j = i + 1; j < KEY_LENGTH; j++){
	double x = find_threshold(16, *cost[i][j]);
 	for(int u = 0; u < 256; u++) 	
	    for(int v = 0; v < 256; v++)
		if((*cost[i][j])[u][v] < x){
		    votes[i][u]++;
		    votes[j][v]++;
		}	    
    }

    for(int i = 0; i < KEY_LENGTH; i++){
	int u = find_max(votes[i], 256);
	key[i] = u;
    }
}

void compute_cost_table(timing_data* data, cost_table cost, key_data truekey){
    for(int i = 0; i < KEY_LENGTH; i++){
	for(int j = 0; j < KEY_LENGTH; j++)
	    if(j <= i)
		cost[i][j] = NULL;
	    else
		cost[i][j] = (large_table*) malloc(sizeof(large_table));
    }

    // print statistics
    for(int i = 0; i < KEY_LENGTH; i++){
	printf("%2d:", i);
	for(int j = 1; j <= i; j++)
	    printf("      ");
	for(int j = i + 1; j < KEY_LENGTH; j++){
	    compute_cost(i, j, data, *cost[i][j]);
	    printf("%5d ", count_below((*cost[i][j])[truekey[i]][truekey[j]], *cost[i][j], 0, 255, 0, 255));
/*	    printf("%3d/%3d ", 
		count_below((*cost[i][j])[key[i]][key[j]], *cost[i][j], truekey[i], truekey[i], 0, 255),
		count_below((*cost[i][j])[key[i]][key[j]], *cost[i][j], 0, 255, truekey[j], truekey[j]));
*/	}
	printf("\n");
    }
}

void compute_rank_table(cost_table cost, rank_array rank_row, key_data truekey){
    for(int i = 0; i < KEY_LENGTH; i++)
	for(int j = i+1; j < KEY_LENGTH; j++){
		rank_row[i][j] = (large_char_table *) malloc(sizeof(large_char_table));
		rank_row[j][i] = (large_char_table *) malloc(sizeof(large_char_table));
		compute_row_ranks(*cost[i][j], *rank_row[i][j], *rank_row[j][i]);
	}

    // print statistics for the true key
    printf("Row ranking:\n");
    for(int i = 0; i < KEY_LENGTH; i++){
	printf("%2d:", i);
	for(int j = 0; j < KEY_LENGTH; j++)
	    if(i == j)
		printf("    ");
	    else
		printf("%3d ", (*rank_row[i][j])[truekey[i]][truekey[j]]);
	printf("\n");
    }


    printf("Column ranking:\n");
    for(int i = 0; i < KEY_LENGTH; i++){
	printf("%2d:", i);
	for(int j = 0; j < KEY_LENGTH; j++)
	    if(i == j)
		printf("    ");
	    else
		printf("%3d ", (*rank_row[j][i])[truekey[j]][truekey[i]]);
	printf("\n");
    }
}


int check_data(timing_data* data, key_data key){
    key_data key_guess;
    bool accepted_guess[KEY_LENGTH];
          
    for(int i = 0; i < KEY_LENGTH ; i++)
	accepted_guess[i] = false;

  
    int votes[KEY_LENGTH][256];
    memset(votes, 0, sizeof(votes));

    cost_table cost;
    rank_array rank_row;

    compute_cost_table(data, cost, key);
    compute_rank_table(cost, rank_row, key);

    first_guess(key_guess, cost);
    printf("Initial guess: "); print_key(key_guess, key);

    walk(key_guess, rank_row, key);
    printf("Walk         : "); print_key(key_guess, key);

    return 0;
}



void main(int argc, char** argv){
 
    timing_data * data = (timing_data*) malloc(sizeof ( timing_data));
    init_data(data);
    read_data(data, "xeondata.txt");
    key_data REALKEY = {0x0d, 0x54, 0x1d, 0xe3, 0x9e, 0x12, 0x47, 0x72, 0x89, 0x87, 0x95, 0x6c, 0x05, 0xc8, 0x1e, 0x3a};
    int bytes_guessable = check_data(data, REALKEY);

    getch();

}