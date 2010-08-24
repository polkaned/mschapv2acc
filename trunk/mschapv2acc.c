/*
 *  MsChapV2 Authentication Challenge Cracker
 *
 *  Copyright (C) 2006-2009 Benjamin Charles
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <ctype.h>
#include <getopt.h>
#include <time.h>

#include "mschapv2lib.h"

//
// HELP
// 
char usage[] =
"\n"
"  -- This is a POC of MsChapV2 Authentication Challenge Cracker --\n\n"
" Usage: mschapv2acc [Option] file_auth_in\n"
" file_auth\n"
"    You must provide a binary file which have this structure:\n"
"     1 *int = user name length\n"
"     user_name_lenght *char = user name\n"
"     16 *unsigned char = auth challenge\n"
"     16 *unsigned char = peer challenge\n"
"     8  *unsigned char = challenge\n"
"     24 *unsigned char = response\n"
" Option\n"
" -x\n"
"    Enable cryptanalyse mode\n"
" -r number\n"
"    Specify the number maximal of characters, default is 12 (works only with brute force mode)\n"
" -s\n"
"    Enable MD4 with SSE2 (works only with brute force mode)\n"
" -i\n"
"    Enter password on standard input, disable brute force mode\n"
" -w\n"
"    Specify a dictionary file, disable brute force mode\n"
" -V\n"
"    Verbose mode, output each try (so slow)\n"
"\n";


//
// GLOBAL
//
int CryptA = 0;
int CryptSEEmd4 = 0;
int FileL = 0;
int Mode = 0;
int CTime = 1;
int Verb = 0;
long int NbH = 0;
long int NbP = 0;
time_t T1, T2;
unsigned char Sec[2];
unsigned char Challenge[8];
unsigned char Response[24];
char **TabTest;
int Cnbc;
int nbTabTest;

void test( unsigned char *hash, char *pwd )
{
	double tmpt;
	unsigned char calculated[24];
	int i;

	if ( Verb == 1 )
	{
		printf( "%s :: ", pwd );
		for( i = 0; i < 16; i++ )
		{
			printf( "%02x ", hash[i] );
		}
	printf ( " :: " );
	}

	if ( CryptA == 1 )
	{
		if ( memcmp( Sec, hash+14, 2 ) == 0 )
		{
			ChallengeResponseBIS( Challenge, hash, calculated );
			NbP++;
			if ( memcmp( Response, calculated, 16 ) != 0 )
			{
				if ( Verb == 1 )
				{
					printf( "Not Ok...\n" );
				}
			}
			else
			{
				if ( CTime == 1 )
				{
					T2 = time( NULL );
					tmpt = difftime( T2, T1 );
					printf( "\nPassword Found: %s in %lld Hour(s) %lld Min(s) %lld Sec(s)\n\n", pwd,( ( ( long long int )( tmpt ) ) / 3600 ), ( ( ( ( long long int )( tmpt ) ) % 3600 ) / 60 ), ( ( long long int ) ( tmpt ) % 60 ) );
					printf( "%ld hashes calculated, %ld hashes tested\n", NbH, NbP );
					exit( 0 );
				}
				else
				{
					printf( "\nPassword Found: %s \n\n", pwd );
					exit( 0 );
				}
			}
		}
		else
		{
			if ( Verb == 1 )
			{
				printf( "Not Ok... Excluded!\n" );
			}
		}
	}
	else
	{
		ChallengeResponseBIS( Challenge, hash, calculated );
		NbP++;
		if ( memcmp( Response, calculated, 16 ) != 0 )
		{
			if ( Verb == 1 ) {
				printf( "NonOk...\n" );
			}
		}
		else
		{
			if ( CTime == 1 )
			{
				T2 = time( NULL );
				tmpt = difftime( T2, T1 );
				printf( "\nPassword Found: %s in %lld Hour(s) %lld Min(s) %lld Sec(s)\n\n", pwd, ( ( ( long long int ) ( tmpt ) ) / 3600 ), ( ( ( ( long long int ) ( tmpt ) ) % 3600 ) / 60 ), ( ( long long int ) ( tmpt ) % 60 ) );
				printf( "%ld hashes calculated, %ld hashes tested\n", NbH, NbP );
				exit( 0 );
			}
			else
			{
				printf( "\nPassword Found: %s \n\n", pwd );
				exit( 0 );
			}
		}
	}
}

//  This function help me to pass 4 passwords for test
void x4 ( char *pwd, int nbc )
{
	int i;
	unsigned char Thash[4][16];

	if ( nbTabTest == 4 )
	{
		if ( CryptSEEmd4 == 1 )
		{
			NtPasswordHashSEE2 ( TabTest[0], TabTest[1], TabTest[2], TabTest[3], Thash[0], Thash[1], Thash[2], Thash[3] );
			NbH = NbH + 4;
			for ( i = 0; i < 4 ; i++ )
			{
				test( Thash[i], TabTest[i] );
			}
		}
		else
		{
			for ( i = 0; i < 4 ; i++ ) {
				NtPasswordHash ( TabTest[i], Thash[0] );
				NbH++;
				test( Thash[0], TabTest[i] );
			}
		}
		nbTabTest = 0;
	}
	strcpy ( TabTest[nbTabTest], pwd);
	nbTabTest++;
}


void bf ( int rang, char *pwdt, int lpwdt, char *caract, int lcaract )
{
	int k;

	for ( k = 0; k < lcaract; k++ )
	{
		pwdt[rang-1] = caract[k];
		if ( rang != lpwdt )
		{
			bf( rang+1, pwdt, lpwdt, caract, lcaract );
		}
		x4( pwdt, lpwdt );
	}
}

int main ( int argc, char *argv[] )
{
	//
	// VAR
	//
	extern char *optarg;
	int i, option, fd, nb, nbc, lpwd, k;
	FILE *f_in;
	unsigned int Luser_name;
	char *user_name;
	char lround[255] = "";
	char pdico[255] = "";
	char *caract;
	char inpt[255], c, *pwd0;
	unsigned char auth_challenge[16], peer_challenge[16], response_cmp[8], keys[16], calculatedT[24], hash[16];
	unsigned short int mm;
	
	//
	// MAIN CODE
	// 
	
	if ( argc < 2 )
	{
		printf( usage );
		exit( 0 );
	}
	
	if ( argv[argc-1][0] == '-' )
	{
		printf( "Err: P455 4 Fi14 M4N, wh3r3 i5 Ur fuckin' ch4113ng3 fi13?\n ");
		printf( usage );
		exit( 0 );
	}			

	// Load challenge information
	if ( ( f_in = fopen( argv[argc-1], "r" ) ) == NULL )
	{
		printf( "Err: Open File Failed\n" );
		exit( 0 );
	}
	fread( &Luser_name, 1 * sizeof( int ), 1, f_in );
	user_name = ( char* ) malloc( Luser_name * sizeof( char ) );
	bzero( user_name, Luser_name );
	fread( user_name, Luser_name * sizeof( unsigned char ), 1, f_in );
	fread( auth_challenge, 16 * sizeof( unsigned char ), 1, f_in );
	fread( peer_challenge, 16 * sizeof( unsigned char ), 1, f_in );
	fread( Challenge, 8 * sizeof( unsigned char ), 1, f_in );
	fread( Response, 24 * sizeof( unsigned char ), 1, f_in );
	fclose( f_in );
	FileL = 1;

	// Print challenge information
	printf( "File Loaded:\n" );
	printf( " - UserName: %s\n", user_name );
	printf( " - AuthenticatorChallenge: " );
	for( i = 0; i < 16; i++ )
	{
		printf( "%02x ", auth_challenge[i] );
	}
	printf ( "\n" );
	printf( " - PeerChallenge: " );
	for( i = 0; i < 16; i++ )
	{
		printf( "%02x ", peer_challenge[i] );
	}
	printf ( "\n" );
	printf( " - Challenge: " );
	for( i = 0; i < 8; i++ )
	{
		printf( "%02x ", Challenge[i] );
	}
	printf ( "\n" );
	printf( " - NtResponse: " );
	for( i = 0; i < 24; i++ )
	{
		printf( "%02x ", Response[i] );
	}
	printf ( "\n" );
	
	// Fix the maximal number of caracters
	lpwd = 20;
	
	// Command line options
	while ( ( option = getopt( argc, argv, "r:xVsiw:?" ) ) != -1 )
	{
		switch ( option )
		{
			case 'r' :
				// Maximal number of caracters
				assert( strlen( optarg ) < 255 );
				strncpy( lround, optarg, 255 );
				lpwd = atoi( lround );
				if ( lpwd < 0 || lpwd > 128 )
				{
					printf( "Err. Number Of Caracters Is Wrong\n");
					exit( 0 );
				}
				printf ( "Number cart. maxi: %i\n", lpwd );
				break;
			case 'x' :
				// Cryptanalysis
				if ( FileL == 1 )
				{
					CryptA = 1;
					printf( "Cryptanalysis In Progress ...\n" );
					memset( response_cmp, 0, sizeof( response_cmp ) );
					memcpy( response_cmp, Response+15, 8 );
					mm = 0;
					fd = 0;
					for ( nb=0; nb <= 65535; nb++ ) {
						if ( fd == 0 ) {
							memset( keys, 0, sizeof( keys ) );
							memcpy( keys+14, &mm, 2 );
							ChallengeResponse( Challenge, keys, calculatedT );
							if ( ( memcmp( calculatedT+16, Response+16, 8 ) ) == 0 )
							{
								printf( "Cryptanalysis Succeeded !\n" );
								memcpy( Sec, keys+14, 2 );
								fd = 1;
							}
							mm++;
						}
					}
					if ( fd == 0 )
					{
						printf( "Err: Cryptanalysis Failed\n" );
						exit( 0 );
					}			
				}
				else
				{
					printf( "Err: No File Loaded\n" );
					exit( 0 );
				}
				break;
			case 'V' :
				// Verbose
				Verb = 1;
				break;
			case 's' :
				// Enable MD4 SSE2
				CryptSEEmd4 = 1;
				printf( "MD4 SSE2 Enabled (works for Brute Force mode only)\n" );
				break;
			case 'i' :
				// std Input
				Mode = 1;
				CTime = 0;
				break;
			case 'w' :
				// Dictionary
				Mode = 2;
				CTime = 0;
				assert( strlen( optarg ) < 255 ); 
				strncpy( pdico, optarg, 255 );
				break;
			case '?' :
				// Display help
				printf( usage );
				exit(99);
				break;
		}
	}
	
	printf( "Login: %s\n", user_name );
	
	if ( Mode == 0 )
	{
		//
		// Mode Brute Force
		// 
		
		printf( "Mode: Brute Force\n" );

		// Char Space - Manual specification
		nbc=62;
		caract = ( char* ) malloc( nbc * sizeof( char ) );
		caract = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
		printf( "Brute Force in progress ...\n" );
		
		T1 = time( NULL );
		for ( i = 1; i <= lpwd; i++ ) {
			pwd0 = ( char* ) malloc( ( i + 1 ) * sizeof( char ) );
			pwd0[i] = '\0';
			TabTest = malloc( 4 * sizeof( char* ) );
			nbTabTest = 0;
			Cnbc = i;
			for ( k = 0; k < 4; k++ )
			{
				TabTest[k] = malloc ( ( i + 1 ) * sizeof( char ) );
				bzero( TabTest[k], ( i + 1 ) );
			}
			// Brute Force
			bf( 1, pwd0, i, caract, nbc );
			// In case we don't test all x4 elts
			nbTabTest = 4;
			x4( TabTest[0], i );
			free( pwd0 );
			for ( k = 0; k < 4 ; k++ )
			{
				free( TabTest[k] );
			}
			free( TabTest );
		}
		
		printf( "\nBrute Force No Succeeded\n" );
		printf( "%ld hashes calculated, %ld hashes tested\n", NbH, NbP );
	}

	if ( Mode == 1 )
	{
		//
		// Standard Input Mode
		//
		
		printf( "Mode: Standard Input\n" );

		printf( "[ctrl+c] to exit\n" );
		
		while ( 1 )
		{
			printf( "Password to test: " );
			scanf( "%s", inpt );
			NtPasswordHash( inpt, hash );
			test( hash, inpt );
			printf( "No match\n" );
		}
	}
	
	if (Mode == 2)
	{
		//
		// Dictionary Mode
		// 

		printf( "Mode Dictionary\n" );

		if ( ( f_in = fopen( pdico, "r" ) ) == NULL )
		{
			printf( "Err: Open Dico File Failed\n" );
			exit( 0 );
		}

		printf( "Parsing Dictionary ...\n" );
		
		i = 0;
		c = getc( f_in );
		while ( c != EOF )
		{
			while ( c != '\n' )
			{
				inpt[i] = c;
				i++;
				c = getc( f_in );
			}
			inpt[i] = '\0';
			if ( Verb == 1 )
			{
				printf( "%s\n", inpt );
            }
			NtPasswordHash ( inpt, hash );
			test( hash, inpt );
			i = 0;
			c = getc( f_in );
		}
		fclose( f_in );
		
		printf( "\nDictionary No succeeded\n" );
	}
	
	return( 0 );
}

