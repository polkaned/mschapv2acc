#ifndef _MSCHAPV2LIB_H
#define _MSCHAPV2LIB_H

void NtPasswordHash( char *Password, unsigned char *PasswordHash );

void NtPasswordHashSEE2( char *Password1, char *Password2, char *Password3, char *Password4, unsigned char *PasswordHash1, unsigned char *PasswordHash2, unsigned char *PasswordHash3, unsigned char *PasswordHash4 );

void DesEncrypt( unsigned char *Clear, unsigned char *Key, unsigned char *Cypher );

void ChallengeResponse( unsigned char *Challenge, unsigned char *PasswordHash, unsigned char *Response );

void ChallengeResponseBIS( unsigned char *Challenge, unsigned char *PasswordHash, unsigned char *Response );

#endif /* mschapv2lib.h */
