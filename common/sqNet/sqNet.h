#ifndef SQNET_H
#define SQNET_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "socket.h"

typedef struct ssl_st	  SSL;
typedef struct ssl_ctx_st SSL_CTX;

typedef struct Client
{
	struct sockaddr_in addr;
	int				   sockfd;
	int				   connected;
	time_t			   last_seen;
	uint64_t		   client_id;
	uint32_t		   encryption_key[32];
	uint32_t		   secret_key;
	uint64_t		   key_salt;
	int				   keys_ready;
	uint32_t		   rel_send_seq;
	uint32_t		   rel_expect_seq;
	uint32_t		   rel_pending_seq;
	uint8_t*		   rel_pending_data;
	size_t			   rel_pending_len;
	uint64_t		   rel_last_send_ms;
	int				   rel_retries;
	int				   rel_waiting_ack;
	uint64_t		   replay_ring[64];
	uint8_t			   replay_ring_pos;
	int				   hs_pending;
	uint64_t		   hs_client_nonce;
	uint64_t		   hs_server_nonce;
	uint8_t			   hs_client_pub[32];
	uint8_t			   hs_server_priv[32];
	uint8_t			   hs_server_pub[32];
	uint8_t			   hs_shared_secret[32];
	struct Client*	   next;
} Client;

typedef struct Conn
{
	int				   sockfd;
	struct sockaddr_in addr;
	int				   is_listener;
	Client*			   clients;
	int				   flags;
	uint32_t		   encryption_key[32];
	uint32_t		   secret_key;
	uint64_t		   key_salt;
} Conn;

typedef enum
{
	CONN_FLAG_NONBLOCK = 1 << 0,
	CONN_FLAG_APPEND = 1 << 1,
	CONN_FLAG_ASYNC = 1 << 2,
	CONN_FLAG_SYNC = 1 << 3,
	CONN_FLAG_DSYNC = 1 << 4,
	CONN_FLAG_RSYNC = 1 << 5,
	CONN_FLAG_NOATIME = 1 << 6,
	CONN_FLAG_DIRECT = 1 << 7,
	CONN_FLAG_LARGEFILE = 1 << 8,
	CONN_FLAG_NDELAY = 1 << 9,
	CONN_FLAG_CLOEXEC = 1 << 10,
	CONN_FLAG_PATH = 1 << 11,
	CONN_FLAG_TMPFILE = 1 << 12
} ConnFlags;

void conn_init( void );
void conn_cleanup( void );

Conn	conn_socket( void );
int		conn_connect( Conn* conn, const char* host, uint16_t port );
int		conn_bind( Conn* conn, const char* host, uint16_t port );
void	conn_close( Conn* conn );
int		conn_recv( Conn* conn, void* buf, size_t size, Client** sender );
int		conn_send( Conn* conn, const void* data, size_t len, Client* client );
int		conn_fileno( Conn* conn );
int		conn_wait( Conn* conn, int timeout_ms );
Client* conn_clients( Conn* conn );
int		conn_set_flags( Conn* conn, int flags_for_set, int flags_for_clear );
int		conn_get_flags( Conn* conn );

#endif
