#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "alg.h"

unsigned int scratch = 0;

const char * alg_name(){

#ifdef XHS_ATTACK
    return "Expanded Home-Stretch Attack";
#elif defined(HS_ATTACK)
    return "Home-Stretch Attack";
#elif defined(W_ATTACK)
    return "Warmup Attack";
#else  
  return "Unknown Algorithm";
#endif
}

int timing_sample(key_data * key, timing_pair * data)
{  

  int i;
  unsigned int timing = 0;
  unsigned char plaintext[16];

  for (i = 0;i < 16;++i) 
    data->value[i] = plaintext[i] = random();  

  timing = timestamp();

#ifdef W_ATTACK
  encrypt(plaintext, plaintext,  key);  
#elif defined(DECRYPT_MODE)
  decrypt(plaintext, data->value,  key);  
#else
  encrypt(plaintext, data->value,  key);  
#endif

  for (i = 0;i < 16;++i) 
    scratch += data->value[i];

  timing = timestamp() - timing;

  data->time = timing;

  return scratch;
}

#ifdef XHS_ATTACK
#ifdef NONE_AES
  #include "nxhs_alg.c"
#else
  #include "xhs_alg.c"
#endif
#elif defined(HS_ATTACK)
  #include "hs_alg.c"
#elif defined(W_ATTACK)
  #include "w_alg.c"
#endif

