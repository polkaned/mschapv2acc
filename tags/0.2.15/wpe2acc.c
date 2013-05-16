/*
 * Hexa (FreeRADIUS WPE) To Bin MsChapV2 Authentication Challenge (Information Converter)
 *
 * Copyright (C) 2008 Benjamin Charles
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 * Thanks a lot to Romain Levy to help me to make this so quickly
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char usage[] =
"\n"
"  $-----------------------------------------$\n"
"  -- Convert Hexa format of FreeRADIUS WPE --\n"
"  --      To bin format for mschav2acc     --\n"
"  $-----------------------------------------$\n\n"
" Usage: wpe2acc file_auth_out\n";

int main ( int argc, char *argv[] )
{

int Luser_name = 0;
char user_name[255];
FILE *f_out;
unsigned int Val0, Val1, Val2, Val3, Val4, Val5, Val6, Val7, Val8, Val9, Val10, Val11, Val12, Val13, Val14, Val15, Val16, Val17, Val18, Val19, Val20, Val21, Val22, Val23;
unsigned char Challenge[8];
unsigned char Response[24];
unsigned char blank16[16];

memset( blank16, 0, sizeof( blank16 ) );

if ( argc < 2 )
{
	printf( usage );
	exit( 0 );
}

printf( "Just Copy/Paste the right information when needed\n");

printf( "username: " );
scanf( "%s", user_name );
Luser_name = strlen( user_name );

printf( "challenge: " );
scanf( "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", &Val0, &Val1, &Val2, &Val3, &Val4, &Val5, &Val6, &Val7 );
Challenge[0] = (unsigned char)Val0;
Challenge[1] = (unsigned char)Val1;
Challenge[2] = (unsigned char)Val2;
Challenge[3] = (unsigned char)Val3;
Challenge[4] = (unsigned char)Val4;
Challenge[5] = (unsigned char)Val5;
Challenge[6] = (unsigned char)Val6;
Challenge[7] = (unsigned char)Val7;

printf( "response: " );
scanf( "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", &Val0, &Val1, &Val2, &Val3, &Val4, &Val5, &Val6, &Val7, &Val8,&Val9, &Val10, &Val11, &Val12, &Val13, &Val14, &Val15, &Val16, &Val17, &Val18, &Val19, &Val20, &Val21, &Val22, &Val23 );
Response[0]  = (unsigned char)Val0;
Response[1]  = (unsigned char)Val1;
Response[2]  = (unsigned char)Val2;
Response[3]  = (unsigned char)Val3;
Response[4]  = (unsigned char)Val4;
Response[5]  = (unsigned char)Val5;
Response[6]  = (unsigned char)Val6;
Response[7]  = (unsigned char)Val7;
Response[8]  = (unsigned char)Val8;
Response[9]  = (unsigned char)Val9;
Response[10] = (unsigned char)Val10;
Response[11] = (unsigned char)Val11;
Response[12] = (unsigned char)Val12;
Response[13] = (unsigned char)Val13;
Response[14] = (unsigned char)Val14;
Response[15] = (unsigned char)Val15;
Response[16] = (unsigned char)Val16;
Response[17] = (unsigned char)Val17;
Response[18] = (unsigned char)Val18;
Response[19] = (unsigned char)Val19;
Response[20] = (unsigned char)Val20;
Response[21] = (unsigned char)Val21;
Response[22] = (unsigned char)Val22;
Response[23] = (unsigned char)Val23;

if ( ( f_out = fopen( argv[argc-1], "w" ) ) == NULL )
{
	printf( "Err: Open File To Write Failed\n" );
	exit( 0 );
}

fwrite( &Luser_name, 1, 1 * sizeof( int ), f_out );
fwrite( user_name, 1, Luser_name * sizeof( unsigned char ), f_out );
fwrite( blank16, 1, 16 * sizeof( unsigned char ), f_out );
fwrite( blank16, 1, 16 * sizeof( unsigned char ), f_out );
fwrite( Challenge, 1, 8 * sizeof( unsigned char ), f_out );
fwrite( Response, 1, 24 * sizeof( unsigned char ), f_out );
fclose( f_out );	

return( 0 );
}

