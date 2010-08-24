/*
 * The follow functions are issued of RFC 1186/1320 compliant Microsoft PPP CHAP Extensions Version 2 implementation
 *
 * Copyright (C) 2006-2009  Benjamin CHARLES
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License, version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301  USA
 */

#include "md4.h"
#include "des.h"
#include "md4sse2.h"
#include <stdio.h>
#include <string.h>


void Ascii2Unicode( char *Ascii, int Nbc, unsigned char *Unicode )
{
	int i;

	bzero( Unicode, Nbc * 2 );
	for ( i = 0; i < Nbc; i++ )
	{
		Unicode[i*2] = Ascii[i];
	}
}


void NtPasswordHash( char *Password, unsigned char *PasswordHash )
{
/* RFC 1186/1320
 * IN 0-to-256-unicode-char Password
 * OUT 16-octet PasswordHash
 */

	unsigned char PasswordUC[256];
	int nbc;

	nbc = strlen( Password );
	if ( ( nbc * 2 ) >= 256 )
	{
		nbc = 128;
	}
	Ascii2Unicode ( Password, nbc, PasswordUC );

	/* RFC 1186/1320
	 * Use the MD4 algorithm to irreversibly hash Password into PasswordHash. Only the password is hashed without including any terminating 0.
	 */
	md4_context ctx;
	md4_starts( &ctx );
	md4_update( &ctx, PasswordUC, ( nbc * 2 ) );
	md4_finish( &ctx, PasswordHash );

}


unsigned char TPasswordUC[4][20] =
{
	"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
	"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
	"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
	"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
};


void NtPasswordHashSEE2( char *Password1, char *Password2, char *Password3, char *Password4, unsigned char *PasswordHash1, unsigned char *PasswordHash2, unsigned char *PasswordHash3, unsigned char *PasswordHash4 )
{
	unsigned char hashX4[64];
	int nbc;
	
	nbc = strlen( Password1 );
	if ( ( nbc * 2 ) >= 256 )
	{
		nbc = 128;
	}
	
	Ascii2Unicode ( Password1, nbc, TPasswordUC[0] );
	Ascii2Unicode ( Password2, nbc, TPasswordUC[1] );
	Ascii2Unicode ( Password3, nbc, TPasswordUC[2] );
	Ascii2Unicode ( Password4, nbc, TPasswordUC[3] );

	md4sse2( TPasswordUC, ( nbc * 2 ), hashX4 );
	
	memcpy( PasswordHash1, hashX4, 16 );
	memcpy( PasswordHash2, hashX4+16, 16 );
	memcpy( PasswordHash3, hashX4+32, 16 );
	memcpy( PasswordHash4, hashX4+48, 16 );

	__asm( "emms" );

}


void DesEncrypt ( unsigned char *Clear, unsigned char *Key, unsigned char *Cypher )
{
/* RFC 1186/1320
 * IN 8-octet Clear
 * 7-octet Key
 * 8-octet Cypher
 */

	unsigned char key0[8];
	int i;

	/* RFC 1186/1320
	 * Use the DES encryption algorithm in ECB mode to encrypt Clear into Cypher such that Cypher can only be decrypted back to Clear by providing Key. Note that the DES algorithm takes as input a 64-bit stream where the 8th, 16th, 24th, etc. bits are parity bits ignored by the encrypting algorithm. Unless you write your own DES to accept 56-bit input without parity, you will need to insert the parity bits yourself.
	 */
	memset( key0, 0, sizeof( 8 ) );
	key0[0] = Key[0] >> 1;
	key0[1] = ( ( Key[0] & 0x01 ) << 6 ) | ( Key[1] >> 2 );
	key0[2] = ( ( Key[1] & 0x03 ) << 5 ) | ( Key[2] >> 3 );
	key0[3] = ( ( Key[2] & 0x07 ) << 4 ) | ( Key[3] >> 4 );
	key0[4] = ( ( Key[3] & 0x0F ) << 3 ) | ( Key[4] >> 5 );
	key0[5] = ( ( Key[4] & 0x1F ) << 2 ) | ( Key[5] >> 6 );
	key0[6] = ( ( Key[5] & 0x3F ) << 1 ) | ( Key[6] >> 7 );
	key0[7] = Key[6] & 0x7F;
	for ( i = 0; i < 8; i++ )
	{
		key0[i] = ( key0[i] << 1 );
	}

	des_context_e ctx;
	des_set_key_esk( &ctx, key0 ) ;
	des_encrypt( &ctx, Clear, Cypher );
}


void ChallengeResponse ( unsigned char *Challenge, unsigned char *PasswordHash, unsigned char *Response )
{
/* RFC 1186/1320
 * IN 8-octet Challenge
 * IN 16-octet PasswordHash
 * OUT 24-octet Response
 */
	
	unsigned char ZPasswordHash[21];

	/* RFC 1186/1320
	 * Set ZPasswordHash to PasswordHash zero-padded to 21 octets
	 */
	memset( ZPasswordHash, 0, sizeof( ZPasswordHash ) );
	memcpy( ZPasswordHash, PasswordHash, 16 );

	/* RFC 1186/1320
	 * DesEncrypt( Challenge, 1st 7-octets of ZPasswordHash, giving 1st 8-octets of Response )
	 */
	DesEncrypt( Challenge, ZPasswordHash, Response );	

	/* RFC 1186/1320
	 * DesEncrypt( Challenge, 2nd 7-octets of ZPasswordHash, giving 2nd 8-octets of Response )
	 */
	DesEncrypt( Challenge, ZPasswordHash+7, Response+8 );

	/* RFC 1186/1320
	 * DesEncrypt( Challenge, 3rd 7-octets of ZPasswordHash, giving 3rd 8-octets of Response )
	 */
	DesEncrypt( Challenge, ZPasswordHash+14, Response+16 );
}


void ChallengeResponseBIS ( unsigned char *Challenge, unsigned char *PasswordHash, unsigned char *Response )
{
	unsigned char ZPasswordHash[21];
	
	memset( ZPasswordHash, 0, sizeof( ZPasswordHash ) );
	memcpy( ZPasswordHash, PasswordHash, 16 );

	DesEncrypt( Challenge, ZPasswordHash, Response );
	DesEncrypt( Challenge, ZPasswordHash+7, Response+8 );
}

