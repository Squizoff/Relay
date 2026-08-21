#ifndef SQNET_INTERNAL_H
#define SQNET_INTERNAL_H

#include "sqNet.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
# include <fcntl.h>
# include <signal.h>
#endif

#include "common.h"

#define SQNET_MAX_PACKET_SIZE ( 65535u - 20u - 8u )

#define CONN_IV_SIZE ( (size_t) sizeof( uint64_t ) )
#define CONN_TIME_SIZE ( (size_t) sizeof( uint64_t ) )
#define CONN_TAG_SIZE 16u
#define CONN_OVERHEAD_SIZE ( CONN_IV_SIZE + CONN_TIME_SIZE + CONN_TAG_SIZE )
#define CONN_PAYLOAD_OFFSET ( (size_t) ( CONN_IV_SIZE + CONN_TIME_SIZE ) )
#define CONN_MAX_DATA_SIZE ( SQNET_MAX_PACKET_SIZE - CONN_OVERHEAD_SIZE )

#define CTRL_MAX_PAYLOAD 512

#define SESSION_KEY_WORDS 32u

extern int sqnet_initialized;

#define CHECK_INIT()                                                                                                                                 \
	do {                                                                                                                                             \
		if ( !sqnet_initialized ) {                                                                                                                  \
			LOGE( "sqNet not initialized!" );                                                                                                        \
			exit( 1 );                                                                                                                               \
		}                                                                                                                                            \
	} while ( 0 )

uint64_t now_ms( void );
time_t	 sqnet_now_sec( void );
int		 is_socket_open( sock_t sockfd );
#ifndef _WIN32
uint64_t htonll( uint64_t v );
uint64_t ntohll( uint64_t v );
#endif
int		same_addr( const struct sockaddr_in* a, const struct sockaddr_in* b );
int		sqnet_send_packet_fd( sock_t sockfd, const uint8_t* payload, size_t payload_len );
int		sqnet_recv_packet_fd( sock_t sockfd, uint8_t* out, size_t out_cap );
Client* find_client_by_sockfd( Conn* conn, sock_t sockfd );

void conn_set_encryption_keys( Conn* conn, const uint32_t new_key[32], uint32_t new_secret_key, uint64_t salt );
void client_set_encryption_keys( Client* c, const uint32_t new_key[32], uint32_t new_secret_key, uint64_t salt );

void	free_client( Client* c );
Client* get_or_add_client( Conn* conn, struct sockaddr_in* addr );
Client* find_client( Conn* conn, const struct sockaddr_in* addr );

uint32_t compute_hash( const uint8_t* data, size_t len, uint32_t secret );
int		 sqnet_generate_x25519_keypair( uint8_t out_public[32], uint8_t out_private[32] );
int		 sqnet_x25519_shared_secret( const uint8_t private_key[32], const uint8_t peer_public[32], uint8_t out_shared[32] );
int		 compute_handshake_proof(
		 const uint8_t shared_secret[32], uint64_t client_nonce, uint64_t server_nonce, uint64_t client_id, uint8_t role_tag, uint8_t out_proof[32] );
void derive_session_keys(
	const uint8_t shared_secret[32], uint64_t client_nonce, uint64_t server_nonce, uint32_t out_key[SESSION_KEY_WORDS], uint32_t* out_secret );

int send_encrypted_payload(
	Conn* conn, const uint32_t key[32], uint32_t secret_key, const uint8_t* payload, size_t payload_len, const struct sockaddr_in* addr );
int openssl_payload_pass( uint8_t* data, size_t data_len, const uint32_t session_key[SESSION_KEY_WORDS], uint32_t session_secret, uint64_t iv,
	uint64_t ts_ms, uint8_t tag[CONN_TAG_SIZE], int encrypt );

void cleanup_stale_assemblies( sock_t sockfd, time_t now );
void cleanup_socket_assemblies( sock_t sockfd );
int	 process_fragmented_payload( Conn* conn, Client* c, const struct sockaddr_in* addr, uint8_t* payload_ptr, size_t payload_len, uint32_t rx_secret,
	 void* buf, size_t size, Client** sender );

int send_fragmented_with_keys(
	Conn* conn, const void* data, size_t len, const uint32_t key[32], uint32_t secret_key, const struct sockaddr_in* addr );

#endif
