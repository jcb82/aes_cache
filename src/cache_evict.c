/*
 * cache_evict.c
 * Joseph C. Bonneau
 * December 2005
 *
 * Wrapper functions around OpenSSL AES calls
 */

#include "cache_evict.h"
#include "time.h"

char * cleaner_start;
char * mem_start;

char * main_start;
char * hs_start;
char * dhs_start;

void cache_evict_init()
{

#ifdef L1_EVICT
 printf("\nEvicting L1 cache");
 mem_start = malloc(L1_CACHE_SIZE);
#elif defined(PENT_4)
 printf("\nEvicting L2 Cache, Pentium IV/Xeon");
#elif defined(PENT_3)
  mem_start = malloc(L2_CACHE_SIZE * 2);
 printf("\nEvicting L2 Cache, Pentium III");

  char * tableStart = getTableStart();
  int tableStartOffset = ((int) tableStart) % L2_CACHE_OFFSET;


   cleaner_start = ((char *) mem_start) - (((int) mem_start) %
		 L2_CACHE_OFFSET) + tableStartOffset ;

  while(cleaner_start < mem_start)
    cleaner_start += L2_CACHE_SIZE;

  main_start = cleaner_start;
  hs_start = main_start + ((int) getHSTableStart()) - ((int) getTableStart());
  dhs_start = main_start + ((int) getDHSTableStart()) - ((int) getTableStart());

#elif defined(SPARC)  
  mem_start = malloc(L2_CACHE_SIZE * 2);
 printf("\nEvicting L2 Cache, SPARC");

  char * tableStart = getTableStart();
  int tableStartOffset = ((int) tableStart) % L2_CACHE_OFFSET;


   cleaner_start = ((char *) mem_start) - (((int) mem_start) %
		 L2_CACHE_OFFSET) + tableStartOffset ;

  while(cleaner_start < mem_start)
    cleaner_start += L2_CACHE_SIZE;

  main_start = cleaner_start;
  hs_start = main_start + ((int) getHSTableStart()) - ((int) getTableStart());
  dhs_start = main_start + ((int) getDHSTableStart()) - ((int) getTableStart());

#endif


/*   char * tableStart = getTableStart(); */
/*   int tableStartOffset = ((int) tableStart) % L2_CACHE_OFFSET; */

/*   printf("\nTe3 at %p", getTableStart()); */
/*   printf("\nTe4 at %p", getHSTableStart()); */
/*   printf("\nTd4 at %p", getDHSTableStart()); */

/*   printf("\nAllocated memory for cache cleaner at address %p", mem_start); */
/*   printf("\nAES table starts at address: %p", tableStart); */
/*   printf("\nAES table maps to offset: %p", tableStartOffset) */

 /*  cleaner_start = ((char *) mem_start) - (((int) mem_start) % */
/*   L2_CACHE_OFFSET) + tableStartOffset ; */

/*   while(cleaner_start <= mem_start) */
/*     cleaner_start += L2_CACHE_SIZE; */

/*   main_start = cleaner_start; */
/*   hs_start = main_start + ((int) getHSTableStart()) - ((int) getTableStart()); */
/*   dhs_start = main_start + ((int) getDHSTableStart()) - ((int) getTableStart()); */

/*   printf("\nTe3 start at %p", main_start); */
/*   printf("\nTe4 start at %p", hs_start); */
/*   printf("\nTd4 start at %p", dhs_start); */

/*   printf("\nCleaner start: %p\n", cleaner_start); */
/*   printf("\nTable start: %p\n", tableStart); */
/*   printf("\nMod CACHE_OFFSET = : %d\n", ((int) cleaner_start - (int) tableStart ) */
/* 	 % L2_CACHE_OFFSET); */
}

/* void cache_clean(char * start){ */
/*   int i, j; */

/*   char * index = main_start; */

/*   int bytesTouched = 0; */

/*   for(j = 0; j < L2_CACHE_ASSOC; j++){ */
/*     for(i = 0; i < TABLE_SIZE; i += L2_CACHE_LINE_SIZE){ */
/*       ++index[i]; */
/*       ++bytesTouched; */
/*     } */
/*     index += L2_CACHE_OFFSET; */
/*   } */

/* } */



void cache_clean(char * start){
  int i, j;
#ifdef PENT_3
  char * index = start; 

  for(j = 0; j < L2_CACHE_ASSOC; j++){
    for(i = 0; i < TABLE_SIZE; i += L2_CACHE_LINE_SIZE)
      ++index[i];
    index += L2_CACHE_OFFSET;
  }

#elif defined(SPARC)
  char * index = start; 

  for(j = 0; j < L2_CACHE_ASSOC; j++){
    for(i = 0; i < TABLE_SIZE; i += L2_CACHE_LINE_SIZE)
      ++index[i];
    index += L2_CACHE_OFFSET;
  }

#elif defined(PENT_4)
    for(i = 0; i < TABLE_SIZE; i += L2_CACHE_LINE_SIZE){
      asm("clflush (%0)" :: "r" (start + i)); 
    }
#endif
}

void l1_cache_evict()
{
  int i;
  for(i = 0; i < L1_CACHE_SIZE; i += L1_LINE_SIZE)
    mem_start[i]++;

}

void w_cache_evict()
{

#ifdef L1_EVICT
  l1_cache_evict();
#elif defined(PENT_3)
  cache_clean(main_start);
  cache_clean(main_start + 1024);
  cache_clean(main_start + 2048);
  cache_clean(main_start + 3072);
#elif defined(SPARC)
  cache_clean(main_start);
  cache_clean(main_start + 1024);
  cache_clean(main_start + 2048);
  cache_clean(main_start + 3072);
#else
  cache_clean(getTableStart());
  cache_clean(getTableStart() + 1024);
  cache_clean(getTableStart() + 2048);
  cache_clean(getTableStart() + 3072);
#endif
}


void hs_cache_evict(){
#ifdef L1_EVICT
  l1_cache_evict();
#elif defined(PENT_3)
  cache_clean(hs_start);
#elif defined(SPARC)
  cache_clean(hs_start);
#else
  cache_clean(getHSTableStart());
#endif

}
void dhs_cache_evict(){
#ifdef L1_EVICT
  l1_cache_evict();
#elif defined(PENT_3)
  cache_clean(dhs_start);
#elif defined(SPARC)
  cache_clean(dhs_start);
#else  
  cache_clean(getDHSTableStart());
#endif
}
/*
 * Get accurate cycle count from processor.
 */
unsigned int timestamp(void)
{

#ifdef SPARC

 unsigned int x;		
 asm volatile ("rd %%tick,%0" : "=r"(x));
 return x;		
#else
  unsigned int bottom;
  unsigned int top;
  asm volatile(".byte 15;.byte 49" : "=a"(bottom),"=d"(top));
  return bottom;
#endif
}
