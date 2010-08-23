// (C) 2007 Christophe Devine

#include "md4sse2.h"

void md4sse2( unsigned char passwd[4][20], int len, unsigned char output[64] )
{
	unsigned long *x, *y0, *y1, *y2, *y3;

	memset( buffer, 0, sizeof( buffer ) );

	passwd[0][len] = 0x80;
	passwd[1][len] = 0x80;
	passwd[2][len] = 0x80;
	passwd[3][len] = 0x80;

	x  = (unsigned long *) buffer;
	y0 = (unsigned long *) passwd[0];
	y1 = (unsigned long *) passwd[1];
	y2 = (unsigned long *) passwd[2];
	y3 = (unsigned long *) passwd[3];

	*x++ = *y0++; *x++ = *y1++; *x++ = *y2++; *x++ = *y3++;
	*x++ = *y0++; *x++ = *y1++; *x++ = *y2++; *x++ = *y3++;
	*x++ = *y0++; *x++ = *y1++; *x++ = *y2++; *x++ = *y3++;
	*x++ = *y0++; *x++ = *y1++; *x++ = *y2++; *x++ = *y3++;
	*x++ = *y0++; *x++ = *y1++; *x++ = *y2++; *x++ = *y3++;

	md4_sse( tmpout, buffer, len );

	x  = (unsigned long *)( output      );
	y0 = (unsigned long *)( tmpout      );
	y1 = (unsigned long *)( tmpout + 16 );
	y2 = (unsigned long *)( tmpout + 32 );
	y3 = (unsigned long *)( tmpout + 48 );

	*x++ = *y0++; *x++ = *y1++; *x++ = *y2++; *x++ = *y3++;
	*x++ = *y0++; *x++ = *y1++; *x++ = *y2++; *x++ = *y3++;
	*x++ = *y0++; *x++ = *y1++; *x++ = *y2++; *x++ = *y3++;
	*x++ = *y0++; *x++ = *y1++; *x++ = *y2++; *x++ = *y3++;
	
	passwd[0][len] = 0;
	passwd[1][len] = 0;
	passwd[2][len] = 0;
	passwd[3][len] = 0;
}

