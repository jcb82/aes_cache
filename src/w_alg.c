
#define UNK_BITS 3

#define MIN_T_VALUE 3


/*
 * Initialize timing data values to zeroes.
 */
void init_data(timing_data * data)
{
   data->total_num_timings = 0; 
   data->total_time = 0; 

   int i, j, k;

   for(i = 0; i < NUM_TABLES; ++i)
     for(j = 0; j < NUM_DIFF_SETS; ++j)
       for(k = 0; k < NUM_DIFFS; ++k){
	      data->time[i][j][k] = 0; 
	      data-> time_squared[i][j][k] = 0; 
	      data->num_timings[i][j][k] = 0; 
       }
}

/*
 * Record timing data for one encryption.
 */
void record_timing(timing_data * data, timing_pair * pair)
{
  int i, j, k;

  data->total_num_timings += 1; 
  data->total_time += pair->time; 
  
  for (i = 0;i < 4;++i) {
    int set_index = 0;
    for(j = 0;j < 3;++j) 
      for(k =  j + 1; k < 4; ++k){
	char diff = (pair->value[i + 4 *  j] ^ pair->value[i + 4 * k] ) >> UNK_BITS;
	data->time[i][set_index][diff] += pair->time; 
	data-> time_squared[i][set_index][diff] += pair->time * pair->time; 
	data->num_timings[i][set_index][diff] += 1; 
	++set_index;
      }
  }
}

/*
 * Using a function for each of 6 possible pairings within a "family"
 * 0-> 0 ^ 1 
 * 1-> 0 ^ 2
 * 2-> 0 ^ 3
 * 3-> 1 ^ 2
 * 4-> 1 ^ 3 
 * 5-> 1 ^ 3
 */

//get first byte for pairing index
int get_first_byte(int index)
{
  switch(index){

  case 0: case 1: case 2:
    return 0;
   
  case 3: case 4:
    return 1;

  default:
    return 2;
  }

}

//get second byte for pairing index.
int get_second_byte(int index)
{
  switch(index){

  case 0:
    return 1;
   
  case 1: case 3:
    return 2;

  default:
    return 3;
  }

}


/*
 *Check the value of the differential which was guessed against its two
 *backup values. Using majority voting to assign values.
 */
void check_diff_guess(unsigned char * diff_guess, int checkIndex, 
		      int firstReplaceX, int firstReplaceY, 
		      int secondReplaceX, int secondReplaceY)
{

  if(diff_guess[checkIndex] == 1){
    if(diff_guess[firstReplaceX] != 1 && diff_guess[firstReplaceY] != 1 &&
    diff_guess[secondReplaceX] != 1 && diff_guess[secondReplaceY] != 1 && 
       diff_guess[firstReplaceX] ^ diff_guess[firstReplaceY] == 
       diff_guess[secondReplaceX] ^ diff_guess[secondReplaceY])
      diff_guess[checkIndex] = diff_guess[firstReplaceX] ^ diff_guess[firstReplaceY];
  }

  else  if (diff_guess[firstReplaceX] != 1 && diff_guess[firstReplaceY] != 1 &&
    diff_guess[secondReplaceX] != 1 && diff_guess[secondReplaceY] != 1 && 
	    (diff_guess[firstReplaceX] ^ diff_guess[firstReplaceY]) == 
	    (diff_guess[secondReplaceX] ^ diff_guess[secondReplaceY]) &&
	    (diff_guess[checkIndex] != 
	     (diff_guess[firstReplaceX] ^diff_guess[firstReplaceY]) || 
	     diff_guess[checkIndex] != 
	     (diff_guess[secondReplaceX] ^ diff_guess[secondReplaceY])))

    {
      /*
      printf("\nCheck failed %d %02x, %02x ^ %02x = %02x, %02x ^ %02x = %02x", 
	     checkIndex, diff_guess[checkIndex],
	     diff_guess[firstReplaceX], diff_guess[firstReplaceY] , 
	     diff_guess[firstReplaceX] ^ diff_guess[firstReplaceY], 
	     diff_guess[secondReplaceX], diff_guess[secondReplaceY],
	     diff_guess[secondReplaceX] ^diff_guess[secondReplaceY]);
      */

      diff_guess[checkIndex] = 1;

    }
}

/*
 *Check the guessed values of differentials within a table value against
 *one another. If any differential does not have a majority agreement,
 *mark it as unknown (1).
 */
int solve_table(unsigned char * diff_guess)
{ 

  int i;

  /*
  printf("\n\nBefore:  ");
  for(i  = 0; i < NUM_DIFF_SETS; i++)
    {
      printf("  %02x", diff_guess[i]);
    }
  */
  check_diff_guess(diff_guess, 0, 1, 3, 2, 4);
  check_diff_guess(diff_guess, 1, 0, 3, 2, 5);
  check_diff_guess(diff_guess, 2, 0, 4, 1, 5);
  check_diff_guess(diff_guess, 3, 0, 1, 4, 5);
  check_diff_guess(diff_guess, 4, 0, 2, 3, 5);
  check_diff_guess(diff_guess, 5, 1, 2, 3, 4);

  /*
  printf("\n After: ");
  for(i  = 0; i < NUM_DIFF_SETS; i++)   
    {
      printf("  %02x", diff_guess[i]);
    }
  */


  int relations_found = 0;

  for(i  = 0; i < NUM_DIFF_SETS; i++)
    {
      if(diff_guess[i] != 1)
	relations_found++;
    }

  if(relations_found == 6)
    return 4;

  if(relations_found >= 3)
    return 3;
  
  if(relations_found >= 1)
    return 1;

  return 0;
}


/*
 *Check the collected data. Pick out statistically low values as likely
 *differentials, then check the values picked against one another.
 */
int check_data(timing_data* data, key_data * key){
  int i, j, k;

  double overall_mean = data->total_time / data->total_num_timings;

  unsigned char diff_guess[NUM_TABLES][NUM_DIFF_SETS];
  unsigned char key_guess[KEY_LENGTH];

  for(i = 0; i < NUM_TABLES; ++i)
    for(j = 0; j < NUM_DIFF_SETS; ++j)
      for(k = 0; k < NUM_DIFFS; ++k){
      data->mean[i][j][k] = data->time[i][j][k]/ data->num_timings[i][j][k];
      data->variance[i][j][k] = data->time_squared[i][j][k]/ data->num_timings[i][j][k];
      data->variance[i][j][k]-= data->mean[i][j][k] * data->mean[i][j][k];
      }

  int bytes_guessable = 0;

  
  double byte_total_time;
  long long byte_N;
  double byte_time_squared;

  double byte_mean[NUM_DIFFS];
  double byte_var[NUM_DIFFS];

  int tables_solved = 0;

  for(i = 0; i < NUM_TABLES; ++i){


    int relations_found  = 0 ;
    
    for(j = 0; j < NUM_DIFF_SETS; ++j){

      int sigs_seen= 0;
             
      byte_total_time = 0;
      byte_N = 0;
      byte_time_squared = 0;
      for(k = 0; k < NUM_DIFFS; ++k){
	byte_total_time += data->time[i][j][k];
	byte_N += data->num_timings[i][j][k];
	byte_time_squared += data->time_squared[i][j][k];
      }
	  
      diff_guess[i][j] = 1;

      for(k = 0; k < NUM_DIFFS; ++k){
	double control_mean = (byte_total_time - data->time[i][j][k]) / 
	  (byte_N - data->num_timings[i][j][k]);

	double control_variance = (byte_time_squared - data->time_squared[i][j][k])/
	  (byte_N - data->num_timings[i][j][k]);
	control_variance -= control_mean * control_mean;

	double test_mean = data->mean[i][j][k];

	double test_variance = data->variance[i][j][k];

	double t_value = (control_mean - test_mean) /
	  sqrt((control_variance / (byte_N - data->num_timings[i][j][k])) + 
	       (test_variance / data->num_timings[i][j][k]));

	 if(t_value >= MIN_T_VALUE && (control_mean - test_mean) > 2 && !sigs_seen){
	     sigs_seen++;
	     diff_guess[i][j] = (k << 3) & 0xf8;
	   }
	 else if(t_value >= MIN_T_VALUE && (control_mean - test_mean) > 2){
	   sigs_seen++;


	   diff_guess[i][j] = 1;
	 }

      }
    }

    int bytes_solved = solve_table(diff_guess[i]);

    bytes_guessable += bytes_solved;
    if(bytes_solved == 4)
      tables_solved++;

  }


  printf("\nBytes solved: %d", bytes_guessable);
  printf("\nTables Solved: %d", tables_solved);

  if(bytes_guessable < KEY_LENGTH)
    return 0;

  int num_correct = 0;

  printf("\nReached guessable stage after %lld encryptions!", 
	     data->total_num_timings);
  
  for(i = 0; i < NUM_TABLES; ++i)
    for(j = 0; j < NUM_DIFF_SETS; ++j){

      //inserted endianness switch
      int x1 = (4 * get_first_byte(j) + i);
      int x2 = (4 * get_second_byte(j) + i );

      printf("\nK[%d] ^ K[%d] = %02x", x1, x2, diff_guess[i][j]);

      if(((key->key_byte[x1] ^ key->key_byte[x2]) & 0xf8) ==
	 (diff_guess[i][j] & 0xf8))
	num_correct++;	
      else
	printf("\n\n!!!Guess for K[%d] ^ K[%d] was incorrect!", x1, x2);

    }

  if(num_correct == NUM_TABLES * NUM_DIFF_SETS)
    printf("\nCORRECT!");
  else
    printf("\nINCORRECT!");


  if(bytes_guessable == KEY_LENGTH)
    return 1;

  return 0;
}

void cache_evict(){
     w_cache_evict();
}
