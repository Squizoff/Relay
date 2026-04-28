#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define LOGE( fmt, ... ) ( printf( "[ERROR] " fmt "\n", ##__VA_ARGS__ ) )
#define LOGI( fmt, ... ) ( printf( "[INFO] " fmt "\n", ##__VA_ARGS__ ) )

uint64_t sqrand( void );
int		 sqrand_bytes( unsigned char* buf, int num );

#endif
