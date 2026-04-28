#include "common.h"
#include <openssl/rand.h>

uint64_t sqrand( void )
{
	uint64_t v;
	if ( RAND_bytes( (unsigned char*) &v, sizeof( v ) ) != 1 )
		return 0;
	return v;
}

int sqrand_bytes( unsigned char* buf, int num )
{
	return RAND_bytes( buf, num );
}
