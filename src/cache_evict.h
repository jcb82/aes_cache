/*
 * cache_evict.h
 * Joseph C. Bonneau
 * December 2005
 *
 * Wrapper functions around OpenSSL AES calls
 */

#include <malloc.h>
#include "encrypt.h"
#include "constants.h"

#define TABLE_SIZE 1024

#ifdef PENT_3

#define TIME_CUTOFF 5000

#ifdef SMALL_AES
#define DELTA  32
#define TABLE_MASK 0xe0
#else
#define DELTA  8
#define TABLE_MASK 0xf8
#endif
#define L2_CACHE_LINE_SIZE 32
#define L2_CACHE_SIZE 262144
#define L2_CACHE_ASSOC 8
#define L2_CACHE_OFFSET (L2_CACHE_SIZE / L2_CACHE_ASSOC)

#define L1_LINE_SIZE 32
#define L1_CACHE_SIZE 0x4000

#elif defined(PENT_4)

#define TIME_CUTOFF 2000

#ifdef SMALL_AES
#define DELTA  64
#define TABLE_MASK 0xc0
#else
#define DELTA 16
#define TABLE_MASK 0xf0
#endif

#define L1_LINE_SIZE 32
#define L1_CACHE_SIZE 0x10000

#define L2_CACHE_LINE_SIZE 32

#elif defined(SPARC)

#define TIME_CUTOFF 5000
#define DELTA 16
#define TABLE_MASK 0xf0

#define L2_CACHE_LINE_SIZE 64
#define L2_CACHE_SIZE 4194304
#define L2_CACHE_ASSOC 2
#define L2_CACHE_OFFSET (L2_CACHE_SIZE / L2_CACHE_ASSOC)

#define L1_LINE_SIZE 64
#define L1_CACHE_SIZE 0x10000


#endif

void l1_evict();

void cache_evict_init();
void w_cache_evict();
void hs_cache_evict();
void dhs_cache_evict();

//for use by cache eviction program,
//must be addeded to aes_core.c
char * getTableStart();
char * getHSTableStart();
char * getDHSTableStart();

unsigned int timestamp();
