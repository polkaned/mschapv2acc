// (C) 2007 Christophe Devine
// 2013 Adapted by Romain LEVY for Linux full 64 bits support

#include "md4sse2.h"

void md4sse2( unsigned char passwd[4][20], int len, unsigned char output[64] )
{
#ifdef __LP64__
	unsigned int *x, *y0, *y1, *y2, *y3;
#else
	unsigned long *x, *y0, *y1, *y2, *y3;
#endif

	memset( buffer, 0, sizeof( buffer ) );

	passwd[0][len] = 0x80;
	passwd[1][len] = 0x80;
	passwd[2][len] = 0x80;
	passwd[3][len] = 0x80;

#ifdef __LP64__
	x  = (unsigned int *) buffer;
	y0 = (unsigned int *) passwd[0];
	y1 = (unsigned int *) passwd[1];
	y2 = (unsigned int *) passwd[2];
	y3 = (unsigned int *) passwd[3];
#else
	x  = (unsigned long *) buffer;
	y0 = (unsigned long *) passwd[0];
	y1 = (unsigned long *) passwd[1];
	y2 = (unsigned long *) passwd[2];
	y3 = (unsigned long *) passwd[3];
#endif

	*x++ = *y0++; *x++ = *y1++; *x++ = *y2++; *x++ = *y3++;
	*x++ = *y0++; *x++ = *y1++; *x++ = *y2++; *x++ = *y3++;
	*x++ = *y0++; *x++ = *y1++; *x++ = *y2++; *x++ = *y3++;
	*x++ = *y0++; *x++ = *y1++; *x++ = *y2++; *x++ = *y3++;
	*x++ = *y0++; *x++ = *y1++; *x++ = *y2++; *x++ = *y3++;

	md4_sse( tmpout, buffer, len );

#ifdef __LP64__
	x  = (unsigned int *)( output      );
	y0 = (unsigned int *)( tmpout      );
	y1 = (unsigned int *)( tmpout + 16 );
	y2 = (unsigned int *)( tmpout + 32 );
	y3 = (unsigned int *)( tmpout + 48 );
#else
	x  = (unsigned long *)( output      );
	y0 = (unsigned long *)( tmpout      );
	y1 = (unsigned long *)( tmpout + 16 );
	y2 = (unsigned long *)( tmpout + 32 );
	y3 = (unsigned long *)( tmpout + 48 );
#endif

	*x++ = *y0++; *x++ = *y1++; *x++ = *y2++; *x++ = *y3++;
	*x++ = *y0++; *x++ = *y1++; *x++ = *y2++; *x++ = *y3++;
	*x++ = *y0++; *x++ = *y1++; *x++ = *y2++; *x++ = *y3++;
	*x++ = *y0++; *x++ = *y1++; *x++ = *y2++; *x++ = *y3++;
	
	passwd[0][len] = 0;
	passwd[1][len] = 0;
	passwd[2][len] = 0;
	passwd[3][len] = 0;
}

