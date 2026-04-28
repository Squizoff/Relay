/*
    sqobf.h - single-header data obfuscation (not crypto)

    Usage:
        #define SQOBF_IMPLEMENTATION
        #include "sqobf.h"

	Copyright 2025-2026 Squizoff
	This work is released under CC0 1.0 Universal (Public Domain Dedication)
*/

#ifndef SQOBF_H
#define SQOBF_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
==============================================================================

PUBLIC API

==============================================================================
*/

typedef struct sqobf_ctx sqobf_ctx;

sqobf_ctx* sqobf_create( const uint32_t key[32], uint32_t secret_key );
void	   sqobf_destroy( sqobf_ctx* ctx );
void	   sqobf_zeroize( sqobf_ctx* ctx );

int sqobf_apply( sqobf_ctx* ctx, uint8_t* data, size_t len );
int sqobf_reverse( sqobf_ctx* ctx, uint8_t* data, size_t len );

uint64_t sqobf_getPos( const sqobf_ctx* ctx );
int		 sqobf_setPos( sqobf_ctx* ctx, uint64_t pos );

//============================================================================

#ifdef __cplusplus
}
#endif

/*
==============================================================================

IMPLEMENTATION

==============================================================================
*/
#ifdef SQOBF_IMPLEMENTATION

# include <stdio.h>
# include <stdlib.h>

# ifndef SQOBF_SBOX_SIZE
#  define SQOBF_SBOX_SIZE 256
# endif

# ifndef SQOBF_DERIVED
#  define SQOBF_DERIVED 4
# endif

/* context */
struct sqobf_ctx
{
	uint32_t key[32];
	uint32_t seed;

	uint32_t derived[SQOBF_DERIVED];
	uint8_t	 sbox[SQOBF_SBOX_SIZE];
	uint8_t	 invSbox[SQOBF_SBOX_SIZE];
	uint8_t	 sbox_rot[SQOBF_SBOX_SIZE];
	uint8_t	 inv_sbox_rot[SQOBF_SBOX_SIZE];

	uint32_t combined;
	int		 sboxReady;
	uint64_t streamPos;
};

static void sqobf_secureZero( void* p, size_t n )
{
	volatile unsigned char* v = (volatile unsigned char*) p;
	while ( n-- )
		*v++ = 0;
}

/* helpers */
static inline uint8_t sqobf_rotl8( uint8_t v, unsigned r )
{
	return (uint8_t) ( ( v << r ) | ( v >> ( 8 - r ) ) );
}
static inline uint8_t sqobf_rotr8( uint8_t v, unsigned r )
{
	return (uint8_t) ( ( v >> r ) | ( v << ( 8 - r ) ) );
}
static inline uint32_t sqobf_rotl32( uint32_t x, int r )
{
	return ( x << r ) | ( x >> ( 32 - r ) );
}

static void sqobf_derive( uint32_t out[SQOBF_DERIVED], uint32_t seed )
{
	uint32_t v = seed ^ 0xA5A5A5A5u;
	int		 i;

	for ( i = 0; i < SQOBF_DERIVED; ++i ) {
		v = v * 1664525u + 1013904223u;
		out[i] = v ^ ( v >> ( i + 1 ) );
	}
}

static uint32_t sqobf_mix32( const uint32_t key[32], const uint32_t derived[], uint32_t combined, uint32_t x )
{
	uint32_t t = x ^ combined;
	uint32_t a = t ^ key[t & 31];
	a += derived[x & ( SQOBF_DERIVED - 1 )];
	a = sqobf_rotl32( a, (int) ( a & 31 ) );
	a ^= key[( a >> 8 ) & 31];
	a += 0x9E3779B9u ^ ( a >> 16 );
	return a;
}

static void sqobf_buildSbox( sqobf_ctx* ctx )
{
	uint32_t seed = ctx->seed ^ ctx->combined;
	uint32_t pr = seed ? seed : 0xDEADBEEFu;
	int		 i;

	for ( i = 0; i < SQOBF_SBOX_SIZE; ++i )
		ctx->sbox[i] = (uint8_t) i;

	for ( i = SQOBF_SBOX_SIZE - 1; i > 0; --i ) {
		uint8_t	 t = ctx->sbox[i];
		uint32_t j;
		pr = sqobf_mix32( ctx->key, ctx->derived, ctx->combined, pr + (uint32_t) i );
		j = pr % (uint32_t) ( i + 1 );
		ctx->sbox[i] = ctx->sbox[j];
		ctx->sbox[j] = t;
	}

	for ( i = 0; i < SQOBF_SBOX_SIZE; ++i )
		ctx->invSbox[ctx->sbox[i]] = (uint8_t) i;

	ctx->sboxReady = 1;
}

static uint32_t sqobf_compute( const uint32_t derived[], const uint32_t key[32] )
{
	uint32_t r = derived[0] ^ 0x243F6A88u;
	int		 i;

	for ( i = 0; i < 8; ++i ) {
		r ^= key[i];
		r = sqobf_rotl32( r, ( i * 7 ) & 31 );
		r += key[31 - i];
	}
	r ^= derived[1];
	return r ? r : 0xC0FFEEu;
}

static inline uint32_t sqobf_keystream32( const sqobf_ctx* ctx, uint64_t block )
{
	block ^= block >> 33;
	return sqobf_mix32( ctx->key, ctx->derived, ctx->combined, (uint32_t) block );
}

static inline uint8_t sqobf_evolvedByte( const sqobf_ctx* ctx, uint32_t ks, int byte_idx, int k, uint64_t pos )
{
	uint8_t b = (uint8_t) ( ks >> ( byte_idx * 8 ) );

	k &= 31;

	b ^= (uint8_t) ( pos >> ( byte_idx * 5 ) );
	b ^= (uint8_t) ctx->derived[k & ( SQOBF_DERIVED - 1 )];

	b = ctx->sbox[b];

	b = sqobf_rotl8( b, (unsigned) ( ( k + byte_idx ) & 7 ) );

	return b;
}

static inline uint64_t sqobf_reservePos( sqobf_ctx* ctx, size_t len )
{
	uint64_t p = ctx->streamPos;
	ctx->streamPos = p + (uint64_t) len;
	return p;
}

static inline void sqobf_flip( const sqobf_ctx* ctx, uint8_t* data, size_t len, int apply )
{
	size_t j;

	if ( len < 2 )
		return;

	if ( apply ) {
		for ( j = len - 1; j > 0; --j ) {
			uint8_t	 s = ctx->sbox[(uint8_t) ( j ^ ctx->combined )];
			unsigned r = s & 7;
			data[j - 1] ^= sqobf_rotl8( data[j], r );
		}
	} else {
		for ( j = 1; j < len; ++j ) {
			uint8_t	 s = ctx->sbox[(uint8_t) ( j ^ ctx->combined )];
			unsigned r = s & 7;
			data[j - 1] ^= sqobf_rotl8( data[j], r );
		}
	}
}

static int sqobf_init( sqobf_ctx* ctx, const uint32_t key[32], uint32_t seed )
{
	int i;

	if ( !ctx || !key )
		return -1;
	memset( ctx, 0, sizeof( *ctx ) );
	memcpy( ctx->key, key, sizeof( ctx->key ) );
	ctx->seed = seed;
	sqobf_derive( ctx->derived, seed );
	ctx->combined = sqobf_compute( ctx->derived, ctx->key );
	ctx->sboxReady = 0;
	ctx->streamPos = 0;

	sqobf_buildSbox( ctx );
	for ( i = 0; i < SQOBF_SBOX_SIZE; ++i ) {
		ctx->sbox_rot[i] = sqobf_rotl8( ctx->sbox[i], 3 );
		ctx->inv_sbox_rot[i] = ctx->invSbox[sqobf_rotr8( (uint8_t) i, 3 )];
	}
	return 0;
}

/*
==============================================================================

PUBLIC API IMPLEMENTATION

==============================================================================
*/

/*
==================
sqobf_create

==================
*/
sqobf_ctx* sqobf_create( const uint32_t key[32], uint32_t secret_key )
{
	sqobf_ctx* ctx = (sqobf_ctx*) malloc( sizeof( sqobf_ctx ) );
	if ( !ctx )
		return NULL;
	if ( sqobf_init( ctx, key, secret_key ) != 0 ) {
		free( ctx );
		return NULL;
	}
	return ctx;
}

/*
==================
sqobf_destroy

==================
*/
void sqobf_destroy( sqobf_ctx* ctx )
{
	if ( !ctx )
		return;

	sqobf_zeroize( ctx );
	free( ctx );
}

/*
==================
sqobf_zeroize

==================
*/
void sqobf_zeroize( sqobf_ctx* ctx )
{
	if ( !ctx )
		return;

	sqobf_secureZero( ctx->key, sizeof( ctx->key ) );
	sqobf_secureZero( ctx->derived, sizeof( ctx->derived ) );
	sqobf_secureZero( ctx->sbox, sizeof( ctx->sbox ) );
	sqobf_secureZero( ctx->invSbox, sizeof( ctx->invSbox ) );
	ctx->combined = 0;
	ctx->sboxReady = 0;
	ctx->streamPos = 0;
}

/*
==================
sqobf_getPos

==================
*/
uint64_t sqobf_getPos( const sqobf_ctx* ctx )
{
	if ( !ctx )
		return 0;

	return ctx->streamPos;
}

/*
==================
sqobf_setPos

==================
*/
int sqobf_setPos( sqobf_ctx* ctx, uint64_t pos )
{
	if ( !ctx )
		return -1;

	ctx->streamPos = pos;
	return 0;
}

/*
==================
sqobf_apply

==================
*/
int sqobf_apply( sqobf_ctx* ctx, uint8_t* data, size_t len )
{
	uint64_t start;
	uint64_t pos;
	uint64_t block;
	uint32_t ks;
	uint8_t	 prev = 0;
	size_t	 i;

	if ( !ctx || ( !data && len > 0 ) )
		return -1;
	if ( len == 0 )
		return 0;

	start = sqobf_reservePos( ctx, len );

	pos = start;
	block = pos >> 2;
	ks = sqobf_keystream32( ctx, block );

	for ( i = 0; i < len; ++i, ++pos ) {
		uint64_t new_block = pos >> 2;
		uint8_t	 kb;
		uint8_t	 v;
		if ( new_block != block ) {
			block = new_block;
			ks = sqobf_keystream32( ctx, block );
		}

		kb = sqobf_evolvedByte( ctx, ks, (int) ( pos & 3 ), (int) i, pos );

		v = data[i];

		v ^= kb;

		v ^= sqobf_rotl8( prev, 1 );

		v = ctx->sbox_rot[v];

		data[i] = v;
		prev = v;
	}

	sqobf_flip( ctx, data, len, 1 );

	return 0;
}

/*
==================
sqobf_reverse

==================
*/
int sqobf_reverse( sqobf_ctx* ctx, uint8_t* data, size_t len )
{
	uint64_t start;
	uint64_t pos;
	uint64_t block;
	uint32_t ks;
	uint8_t	 prev = 0;
	size_t	 i;

	if ( !ctx || ( !data && len > 0 ) )
		return -1;
	if ( len == 0 )
		return 0;

	start = sqobf_reservePos( ctx, len );

	sqobf_flip( ctx, data, len, 0 );

	pos = start;
	block = pos >> 2;
	ks = sqobf_keystream32( ctx, block );

	for ( i = 0; i < len; ++i, ++pos ) {
		uint64_t new_block = pos >> 2;
		uint8_t	 kb;
		uint8_t	 v;
		uint8_t	 cur;
		if ( new_block != block ) {
			block = new_block;
			ks = sqobf_keystream32( ctx, block );
		}

		kb = sqobf_evolvedByte( ctx, ks, (int) ( pos & 3 ), (int) i, pos );

		cur = data[i];

		v = ctx->inv_sbox_rot[cur];

		v ^= sqobf_rotl8( prev, 1 );

		v ^= kb;

		data[i] = v;
		prev = cur;
	}
	return 0;
}

#endif // SQOBF_IMPLEMENTATION

#endif // SQOBF_H
