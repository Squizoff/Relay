#include "sqNet_internal.h"
#include <openssl/err.h>
#include <openssl/ssl.h>

int sqnet_initialized = 0;

uint64_t now_ms( void )
{
#ifdef _WIN32
	return (uint64_t) GetTickCount64();
#else
	struct timeval tv;
	gettimeofday( &tv, NULL );
	return (uint64_t) tv.tv_sec * 1000u + (uint64_t) ( tv.tv_usec / 1000u );
#endif
}

time_t sqnet_now_sec( void )
{
#ifdef _WIN32
	return (time_t) ( GetTickCount64() / 1000u );
#else
# ifdef CLOCK_MONOTONIC
	struct timespec ts;
	if ( clock_gettime( CLOCK_MONOTONIC, &ts ) == 0 )
		return (time_t) ts.tv_sec;
# endif
	return time( NULL );
#endif
}

int is_socket_open( int sockfd )
{
	return sockfd >= 0;
}

static int sqnet_send_all( int sockfd, const uint8_t* data, size_t len )
{
	size_t sent_total = 0;

	if ( !data )
		return -1;

	while ( sent_total < len ) {
		ssize_t n;
#if defined( MSG_NOSIGNAL )
		n = send( sockfd, data + sent_total, len - sent_total, MSG_NOSIGNAL );
#else
		n = send( sockfd, data + sent_total, len - sent_total, 0 );
#endif
		if ( n > 0 ) {
			sent_total += (size_t) n;
			continue;
		}

		if ( n == 0 ) {
			return -1;
		}

		if ( errno == EINTR ) {
			continue;
		}
		if ( errno == EAGAIN || errno == EWOULDBLOCK ) {
			fd_set		   wfds;
			struct timeval tv;
			FD_ZERO( &wfds );
			FD_SET( sockfd, &wfds );
			tv.tv_sec = 5;
			tv.tv_usec = 0;
			int sel = select( sockfd + 1, NULL, &wfds, NULL, &tv );
			if ( sel <= 0 ) {
				return -1;
			}
			continue;
		}

		return -1;
	}
	return 0;
}

static int sqnet_recv_all( int sockfd, uint8_t* data, size_t len )
{
	size_t got_total = 0;

	if ( !data )
		return -1;

	while ( got_total < len ) {
		ssize_t n = recv( sockfd, data + got_total, len - got_total, 0 );
		if ( n > 0 ) {
			got_total += (size_t) n;
			continue;
		}
		if ( n == 0 ) {
			return -1;
		}

		if ( errno == EINTR ) {
			continue;
		}
		if ( errno == EAGAIN || errno == EWOULDBLOCK ) {
			fd_set		   rfds;
			struct timeval tv;
			FD_ZERO( &rfds );
			FD_SET( sockfd, &rfds );
			tv.tv_sec = 5;
			tv.tv_usec = 0;
			int sel = select( sockfd + 1, &rfds, NULL, NULL, &tv );
			if ( sel <= 0 ) {
				return -1;
			}
			continue;
		}

		return -1;
	}
	return 0;
}

int sqnet_send_packet_fd( int sockfd, const uint8_t* payload, size_t payload_len )
{
	uint32_t payload_len_be;

	if ( !is_socket_open( sockfd ) || !payload || payload_len == 0 || payload_len > SQNET_MAX_PACKET_SIZE || payload_len > (size_t) UINT32_MAX )
		return -1;

	payload_len_be = htonl( (uint32_t) payload_len );
	if ( sqnet_send_all( sockfd, (const uint8_t*) &payload_len_be, sizeof( payload_len_be ) ) != 0 )
		return -1;

	return sqnet_send_all( sockfd, payload, payload_len );
}

int sqnet_recv_packet_fd( int sockfd, uint8_t* out, size_t out_cap )
{
	uint32_t payload_len_be;
	size_t	 payload_len;

	if ( !is_socket_open( sockfd ) || !out || out_cap == 0 )
		return -1;

	if ( sqnet_recv_all( sockfd, (uint8_t*) &payload_len_be, sizeof( payload_len_be ) ) != 0 )
		return -1;

	payload_len = (size_t) ntohl( payload_len_be );
	if ( payload_len == 0 || payload_len > SQNET_MAX_PACKET_SIZE || payload_len > out_cap )
		return -1;

	if ( sqnet_recv_all( sockfd, out, payload_len ) != 0 )
		return -1;

	return (int) payload_len;
}

void conn_set_encryption_keys( Conn* conn, const uint32_t new_key[32], uint32_t new_secret_key, uint64_t salt )
{
	memcpy( conn->encryption_key, new_key, sizeof( conn->encryption_key ) );
	conn->secret_key = new_secret_key;
	conn->key_salt = salt;
}

void client_set_encryption_keys( Client* c, const uint32_t new_key[32], uint32_t new_secret_key, uint64_t salt )
{
	memcpy( c->encryption_key, new_key, sizeof( c->encryption_key ) );
	c->secret_key = new_secret_key;
	c->key_salt = salt;
	c->keys_ready = 1;
}

void conn_init( void )
{
	socket_init();
#ifndef _WIN32
	signal( SIGPIPE, SIG_IGN );
#endif

	OPENSSL_init_ssl( 0, NULL );
	sqnet_initialized = 1;
}

void conn_cleanup( void )
{
	CHECK_INIT();
	socket_cleanup();
}

uint64_t htonll( uint64_t v )
{
	uint32_t hi = htonl( (uint32_t) ( v >> 32 ) );
	uint32_t lo = htonl( (uint32_t) ( v & (uint64_t) UINT32_MAX ) );
	return ( (uint64_t) lo << 32 ) | hi;
}

uint64_t ntohll( uint64_t v )
{
	uint32_t hi = ntohl( (uint32_t) ( v >> 32 ) );
	uint32_t lo = ntohl( (uint32_t) ( v & (uint64_t) UINT32_MAX ) );
	return ( (uint64_t) lo << 32 ) | hi;
}

int same_addr( const struct sockaddr_in* a, const struct sockaddr_in* b )
{
	return a->sin_addr.s_addr == b->sin_addr.s_addr && a->sin_port == b->sin_port;
}

void free_client( Client* c )
{
	if ( !c )
		return;
	if ( is_socket_open( c->sockfd ) ) {
		close( c->sockfd );
	}
	memset( c->encryption_key, 0, sizeof( c->encryption_key ) );
	c->secret_key = 0;
	c->key_salt = 0;
	memset( c->hs_server_priv, 0, sizeof( c->hs_server_priv ) );
	memset( c->hs_shared_secret, 0, sizeof( c->hs_shared_secret ) );
	free( c->rel_pending_data );
	c->rel_pending_data = NULL;
	free( c );
}

Client* get_or_add_client( Conn* conn, struct sockaddr_in* addr )
{
	Client* c = conn->clients;
	while ( c ) {
		if ( c->addr.sin_addr.s_addr == addr->sin_addr.s_addr && c->addr.sin_port == addr->sin_port )
			return c;
		c = c->next;
	}

	c = (Client*) calloc( 1, sizeof( Client ) );
	if ( !c )
		return NULL;

	c->addr = *addr;
	c->sockfd = -1;
	c->connected = 1;
	c->last_seen = sqnet_now_sec();
	c->client_id = sqrand();
	if ( c->client_id == 0 )
		c->client_id = 1;
	c->next = conn->clients;
	conn->clients = c;
	return c;
}

Client* find_client_by_sockfd( Conn* conn, int sockfd )
{
	Client* c;

	if ( !conn || !is_socket_open( sockfd ) )
		return NULL;

	c = conn->clients;
	while ( c ) {
		if ( c->sockfd == sockfd )
			return c;
		c = c->next;
	}
	return NULL;
}

Client* find_client( Conn* conn, const struct sockaddr_in* addr )
{
	Client* c;

	if ( !conn || !addr )
		return NULL;

	c = conn->clients;
	while ( c ) {
		if ( c->addr.sin_addr.s_addr == addr->sin_addr.s_addr && c->addr.sin_port == addr->sin_port )
			return c;
		c = c->next;
	}

	return NULL;
}

Conn conn_socket( void )
{
	Conn conn;

	CHECK_INIT();
	memset( &conn, 0, sizeof( conn ) );

	conn.sockfd = socket( AF_INET, SOCK_STREAM, 0 );
	if ( conn.sockfd < 0 ) {
		LOGE( "socket() failed: %s", socket_error() );
		conn.sockfd = -1;
		return conn;
	}

	return conn;
}

int conn_bind( Conn* conn, const char* host, uint16_t port )
{
	int opt = 1;

	CHECK_INIT();
	if ( !conn || !is_socket_open( conn->sockfd ) )
		return -1;

	setsockopt( conn->sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof( opt ) );
#ifdef SO_REUSEPORT
	setsockopt( conn->sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof( opt ) );
#endif

	memset( &conn->addr, 0, sizeof( conn->addr ) );
	conn->addr.sin_family = AF_INET;
	conn->addr.sin_port = htons( port );
	if ( inet_pton( AF_INET, host, &conn->addr.sin_addr ) <= 0 ) {
		LOGE( "Invalid address: %s", host );
		return -1;
	}

	if ( bind( conn->sockfd, (struct sockaddr*) &conn->addr, sizeof( conn->addr ) ) < 0 ) {
		LOGE( "bind failed: %s", socket_error() );
		return -1;
	}

	if ( listen( conn->sockfd, 64 ) < 0 ) {
		LOGE( "listen failed: %s", socket_error() );
		return -1;
	}
	conn->is_listener = 1;
	return 0;
}

void conn_close( Conn* conn )
{
	Client* c;

	CHECK_INIT();
	if ( !conn )
		return;

	c = conn->clients;
	while ( c ) {
		Client* tmp = c;
		c = c->next;
		if ( tmp->sockfd == conn->sockfd )
			tmp->sockfd = -1;
		free_client( tmp );
	}
	conn->clients = NULL;

	if ( !is_socket_open( conn->sockfd ) ) {
		return;
	}

	cleanup_socket_assemblies( conn->sockfd );
	close( conn->sockfd );
	conn->sockfd = -1;
}

int conn_fileno( Conn* conn )
{
	CHECK_INIT();
	return conn && is_socket_open( conn->sockfd ) ? conn->sockfd : -1;
}

int conn_wait( Conn* conn, int timeout_ms )
{
	CHECK_INIT();
	if ( !conn || !is_socket_open( conn->sockfd ) )
		return -1;

	fd_set			readfds;
	struct timeval	tv;
	struct timeval* ptv = NULL;
	int				maxfd = conn->sockfd;
	Client*			c = conn->clients;

	FD_ZERO( &readfds );
	FD_SET( conn->sockfd, &readfds );
	while ( c ) {
		if ( is_socket_open( c->sockfd ) ) {
			FD_SET( c->sockfd, &readfds );
			if ( c->sockfd > maxfd )
				maxfd = c->sockfd;
		}
		c = c->next;
	}
	if ( timeout_ms >= 0 ) {
		tv.tv_sec = timeout_ms / 1000;
		tv.tv_usec = ( timeout_ms % 1000 ) * 1000;
		ptv = &tv;
	}

	{
		int ret = select( maxfd + 1, &readfds, NULL, NULL, ptv );
		if ( ret < 0 ) {
#ifdef _WIN32
			if ( s_errno == WSAEINTR )
				return 0;
#else
			if ( s_errno == EINTR )
				return 0;
#endif
			LOGE( "select failed: %s", socket_error() );
			return -1;
		}
		return ret > 0 ? 1 : 0;
	}
}

Client* conn_clients( Conn* conn )
{
	return conn ? conn->clients : NULL;
}

struct
{
	int conn_flag;
	int os_flag;
} mapping[] = {
	{ CONN_FLAG_NONBLOCK, O_NONBLOCK },
	{ CONN_FLAG_APPEND, O_APPEND },
	{ CONN_FLAG_ASYNC, O_ASYNC },
	{ CONN_FLAG_SYNC, O_SYNC },
	{ CONN_FLAG_DSYNC, O_DSYNC },
#ifdef O_RSYNC
	{ CONN_FLAG_RSYNC, O_RSYNC },
#endif
#ifdef O_NOATIME
	{ CONN_FLAG_NOATIME, O_NOATIME },
#endif
#ifdef O_DIRECT
	{ CONN_FLAG_DIRECT, O_DIRECT },
#endif
#ifdef O_LARGEFILE
	{ CONN_FLAG_LARGEFILE, O_LARGEFILE },
#endif
#ifdef O_NDELAY
	{ CONN_FLAG_NDELAY, O_NDELAY },
#endif
#ifdef O_CLOEXEC
	{ CONN_FLAG_CLOEXEC, O_CLOEXEC },
#endif
#ifdef O_PATH
	{ CONN_FLAG_PATH, O_PATH },
#endif
#ifdef O_TMPFILE
	{ CONN_FLAG_TMPFILE, O_TMPFILE },
#endif
};

int conn_set_flags( Conn* conn, int flags_for_set, int flags_for_clear )
{
	CHECK_INIT();
	if ( !conn || !is_socket_open( conn->sockfd ) )
		return -1;

	conn->flags &= ~flags_for_clear;
	conn->flags |= flags_for_set;

#ifdef _WIN32
	if ( flags_for_set & CONN_FLAG_NONBLOCK ) {
		u_long mode = 1;
		ioctlsocket( conn->sockfd, FIONBIO, &mode );
	}
	if ( flags_for_clear & CONN_FLAG_NONBLOCK ) {
		u_long mode = 0;
		ioctlsocket( conn->sockfd, FIONBIO, &mode );
	}
	return 0;
#else
	int	   os_flags = fcntl( conn->sockfd, F_GETFL, 0 );
	size_t i;

	if ( os_flags < 0 )
		return -1;

	for ( i = 0; i < sizeof( mapping ) / sizeof( mapping[0] ); ++i ) {
		if ( conn->flags & mapping[i].conn_flag )
			os_flags |= mapping[i].os_flag;
		else
			os_flags &= ~mapping[i].os_flag;
	}

	return fcntl( conn->sockfd, F_SETFL, os_flags );
#endif
}

int conn_get_flags( Conn* conn )
{
	CHECK_INIT();
	if ( !conn || !is_socket_open( conn->sockfd ) )
		return -1;

#ifdef _WIN32
	{
		u_long mode = 0;
		ioctlsocket( conn->sockfd, FIONBIO, &mode );
		return mode ? CONN_FLAG_NONBLOCK : conn->flags;
	}
#else
	int	   result = conn->flags;
	int	   os_flags = fcntl( conn->sockfd, F_GETFL, 0 );
	size_t i;

	if ( os_flags < 0 )
		return -1;

	for ( i = 0; i < sizeof( mapping ) / sizeof( mapping[0] ); ++i ) {
		if ( os_flags & mapping[i].os_flag )
			result |= mapping[i].conn_flag;
	}

	return result;
#endif
}
