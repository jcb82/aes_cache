/*
 * encrypt.h
 * Joseph C. Bonneau
 * December 2005
 *
 * Wrapper functions around OpenSSL AES calls
 */

#ifndef KEY_INVERT_H
#define KEY_INVERT_H

void revert_key(unsigned char * key, 
		 unsigned char * original);

#endif
