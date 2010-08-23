#include <string.h>
#include <stdio.h>

extern int md4_sse( unsigned char *out, unsigned char *in, int n ) __attribute__((regparm(3)));

unsigned char buffer[256];
unsigned char tmpout[64];

void md4sse2( unsigned char passwd[4][20], int len, unsigned char output[64] );
