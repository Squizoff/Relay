#include "sqNet_internal.h"
#include "sqobf.h"
#include <openssl/crypto.h>

#ifndef _WIN32
# include <netinet/tcp.h>
#endif

#define CONN_PLAIN_LEN_SIZE ( (size_t) sizeof( uint16_t ) )
#define ENC_CTRL_HEADER_SIZE ( 1u + 2u )
#define HS_HEADER_SIZE ( 1u + 2u )
#define HS_TYPE_CLIENT_HELLO 0x01u
#define HS_TYPE_SERVER_HELLO 0x02u
#define HS_TYPE_CLIENT_FINISH 0x03u
#define HS_PROOF_SIZE 32u
#define HS_ROLE_SERVER 0x53u
#define HS_ROLE_CLIENT 0x43u

static void conn_remove_client( Conn* conn, Client* target )
{
	Client** pp;

	if ( !conn || !target )
		return;

	pp = &conn->clients;
	while ( *pp ) {
		if ( *pp == target ) {
			*pp = target->next;
			free_client( target );
			return;
		}
		pp = &( *pp )->next;
	}
}

static int conn_accept_client( Conn* conn )
{
	struct sockaddr_in peer_addr;
	socklen_t		   peer_len = sizeof( peer_addr );
	sock_t			   fd;
	Client*			   c;

	if ( !conn || !conn->is_listener || !is_socket_open( conn->sockfd ) )
		return -1;

	fd = accept( conn->sockfd, (struct sockaddr*) &peer_addr, &peer_len );
	if ( IS_INVALID_SOCKET( fd ) )
		return -1;

	if ( conn->flags & CONN_FLAG_NONBLOCK ) {
#ifdef _WIN32
		u_long mode = 1;
		ioctlsocket( fd, FIONBIO, &mode );
#else
		int f = fcntl( fd, F_GETFL, 0 );
		if ( f >= 0 ) {
			f |= O_NONBLOCK;
			fcntl( fd, F_SETFL, f );
		}
#endif
	}

	{
		int flag = 1;
		setsockopt( fd, IPPROTO_TCP, TCP_NODELAY, (void*) &flag, sizeof( flag ) );
		setsockopt( fd, SOL_SOCKET, SO_KEEPALIVE, (void*) &flag, sizeof( flag ) );
	}

	c = (Client*) calloc( 1, sizeof( Client ) );
	if ( !c )
		goto fail;

	c->addr = peer_addr;
	c->sockfd = fd;
	c->connected = 1;
	c->last_seen = sqnet_now_sec();
	c->client_id = sqrand();
	if ( c->client_id == 0 )
		c->client_id = 1;
	c->next = conn->clients;
	conn->clients = c;
	return 0;

fail:
	close( fd );
	return -1;
}

static int replay_seen_or_mark( Client* c, uint64_t iv )
{
	if ( !c )
		return 0;

	const size_t replay_count = sizeof( c->replay_ring ) / sizeof( c->replay_ring[0] );

	for ( size_t i = 0; i < replay_count; ++i ) {
		if ( c->replay_ring[i] == iv )
			return 1;
	}

	c->replay_ring[c->replay_ring_pos] = iv;
	c->replay_ring_pos = (uint16_t) ( ( c->replay_ring_pos + 1u ) % replay_count );

	return 0;
}

static int parse_encrypted_control(
	const uint8_t* packet, size_t packet_len, uint8_t* type_out, const uint8_t** payload_out, uint16_t* payload_len_out )
{
	uint16_t payload_len;

	if ( !packet || !type_out || !payload_out || !payload_len_out )
		return 0;
	if ( packet_len < ENC_CTRL_HEADER_SIZE )
		return 0;

	payload_len = (uint16_t) ( ( (uint16_t) packet[1u] << 8 ) | (uint16_t) packet[2u] );
	if ( payload_len > CTRL_MAX_PAYLOAD || packet_len != ENC_CTRL_HEADER_SIZE + payload_len )
		return 0;

	*type_out = packet[0];
	*payload_out = packet + ENC_CTRL_HEADER_SIZE;
	*payload_len_out = payload_len;
	return 1;
}

static int send_handshake_plain( Conn* conn, const struct sockaddr_in* addr, uint8_t type, const uint8_t* payload, uint16_t payload_len )
{
	uint8_t packet[HS_HEADER_SIZE + 128u];
	sock_t	out_fd = INVALID_SOCK;
	int		rc;

	if ( !conn || payload_len > sizeof( packet ) - HS_HEADER_SIZE )
		return -1;

	packet[0] = type;
	packet[1u] = (uint8_t) ( payload_len >> 8 );
	packet[2u] = (uint8_t) ( payload_len & 0xFFu );
	if ( payload_len > 0 && payload )
		memcpy( packet + HS_HEADER_SIZE, payload, payload_len );

	if ( conn->is_listener ) {
		Client* c = NULL;
		if ( addr )
			c = find_client( conn, addr );
		if ( !c || !is_socket_open( c->sockfd ) )
			return -1;
		out_fd = c->sockfd;
	} else {
		out_fd = conn->sockfd;
	}

	rc = sqnet_send_packet_fd( out_fd, packet, HS_HEADER_SIZE + payload_len );
	return rc == 0 ? 0 : -1;
}

static int parse_handshake_plain(
	const uint8_t* packet, size_t packet_len, uint8_t* type_out, const uint8_t** payload_out, uint16_t* payload_len_out )
{
	uint16_t payload_len;

	if ( !packet || !type_out || !payload_out || !payload_len_out )
		return 0;
	if ( packet_len < HS_HEADER_SIZE )
		return 0;

	payload_len = (uint16_t) ( ( (uint16_t) packet[1u] << 8 ) | (uint16_t) packet[2u] );
	if ( packet_len != HS_HEADER_SIZE + payload_len )
		return 0;

	*type_out = packet[0];
	*payload_out = packet + HS_HEADER_SIZE;
	*payload_len_out = payload_len;
	return 1;
}

static void clear_handshake_state( Client* c )
{
	if ( !c )
		return;
	c->hs_pending = 0;
	c->hs_client_nonce = 0;
	c->hs_server_nonce = 0;
	memset( c->hs_client_pub, 0, sizeof( c->hs_client_pub ) );
	memset( c->hs_server_priv, 0, sizeof( c->hs_server_priv ) );
	memset( c->hs_server_pub, 0, sizeof( c->hs_server_pub ) );
	memset( c->hs_shared_secret, 0, sizeof( c->hs_shared_secret ) );
}

static int try_decrypt_payload(
	uint8_t* packet_buf, size_t packet_len, const uint32_t rx_key[SESSION_KEY_WORDS], uint32_t rx_secret, size_t* payload_len_out, uint64_t* iv_out )
{
	uint64_t   iv_net;
	uint64_t   iv;
	uint64_t   ts_net;
	uint64_t   ts_ms;
	size_t	   payload_len;
	sqobf_ctx* ctx_sess;
	uint16_t   plain_len_net;
	size_t	   plain_len;
	uint8_t	   tag[CONN_TAG_SIZE];

	if ( !packet_buf || packet_len < CONN_OVERHEAD_SIZE || !payload_len_out )
		return 0;

	memcpy( &iv_net, packet_buf, sizeof( iv_net ) );
	iv = ntohll( iv_net );

	memcpy( &ts_net, packet_buf + CONN_IV_SIZE, sizeof( ts_net ) );
	ts_ms = ntohll( ts_net );

	payload_len = packet_len - CONN_OVERHEAD_SIZE;
	memcpy( tag, packet_buf + packet_len - CONN_TAG_SIZE, CONN_TAG_SIZE );

	if ( openssl_payload_pass( packet_buf + CONN_PAYLOAD_OFFSET, payload_len, rx_key, rx_secret, iv, ts_ms, tag, 0 ) != 0 ) {
		return 0;
	}
	memset( tag, 0, sizeof( tag ) );

	ctx_sess = sqobf_create( rx_key, rx_secret );
	if ( !ctx_sess ) {
		LOGE( "sqobf_create failed (ctx_sess)" );
		return -1;
	}
	if ( sqobf_setPos( ctx_sess, iv ) != 0 || sqobf_reverse( ctx_sess, packet_buf + CONN_PAYLOAD_OFFSET, payload_len ) != 0 ) {
		LOGE( "sqobf_reverse failed (ctx_sess)" );
		sqobf_destroy( ctx_sess );
		return -1;
	}
	sqobf_destroy( ctx_sess );

	if ( payload_len < CONN_PLAIN_LEN_SIZE )
		return 0;

	memcpy( &plain_len_net, packet_buf + CONN_PAYLOAD_OFFSET, sizeof( plain_len_net ) );
	plain_len = (size_t) ntohs( plain_len_net );
	if ( plain_len > payload_len - CONN_PLAIN_LEN_SIZE )
		return 0;

	memmove( packet_buf + CONN_PAYLOAD_OFFSET, packet_buf + CONN_PAYLOAD_OFFSET + CONN_PLAIN_LEN_SIZE, plain_len );
	*payload_len_out = plain_len;
	if ( iv_out )
		*iv_out = iv;
	return 1;
}

int conn_connect( Conn* conn, const char* host, uint16_t port )
{
	uint8_t			   hello_payload[8u + 32u];
	uint8_t			   packet_buf[SQNET_MAX_PACKET_SIZE];
	uint8_t			   client_priv[32];
	uint8_t			   client_pub[32];
	uint8_t			   shared_secret[32];
	uint64_t		   client_nonce;
	uint64_t		   server_nonce = 0;
	uint64_t		   client_id = 0;
	time_t			   deadline;
	struct sockaddr_in server_addr;
	uint8_t			   hs_type = 0;
	const uint8_t*	   hs_payload = NULL;
	uint16_t		   hs_payload_len = 0;
	int				   rc = -1;
	int				   n;
	Client*			   server_client = NULL;
#ifdef _WIN32
	DWORD rcv_timeout = 1000;
	DWORD rcv_timeout_restore = 0;
#else
	struct timeval rcv_timeout = { 1, 0 };
	struct timeval rcv_timeout_restore = { 0, 0 };
#endif

	CHECK_INIT();
	if ( !conn || !is_socket_open( conn->sockfd ) ) {
		LOGE( "Invalid socket" );
		return -1;
	}

	memset( &server_addr, 0, sizeof( server_addr ) );
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons( port );
	if ( inet_pton( AF_INET, host, &server_addr.sin_addr ) <= 0 ) {
		LOGE( "Invalid connect address: %s", host );
		return -1;
	}

	if ( connect( conn->sockfd, (struct sockaddr*) &server_addr, sizeof( server_addr ) ) < 0 ) {
		LOGE( "connect failed: %s", socket_error() );
		return -1;
	}
	{
		int flag = 1;
		setsockopt( conn->sockfd, IPPROTO_TCP, TCP_NODELAY, (void*) &flag, sizeof( flag ) );
		setsockopt( conn->sockfd, SOL_SOCKET, SO_KEEPALIVE, (void*) &flag, sizeof( flag ) );
	}
	conn->addr = server_addr;
	conn->is_listener = 0;

	if ( sqnet_generate_x25519_keypair( client_pub, client_priv ) != 0 ) {
		LOGE( "Failed to generate ephemeral X25519 keypair" );
		goto cleanup;
	}

	client_nonce = sqrand();
	if ( client_nonce == 0 )
		client_nonce = 1;
	{
		uint64_t client_nonce_be = htonll( client_nonce );
		memcpy( hello_payload, &client_nonce_be, sizeof( client_nonce_be ) );
		memcpy( hello_payload + sizeof( client_nonce_be ), client_pub, sizeof( client_pub ) );
	}

	if ( send_handshake_plain( conn, &server_addr, HS_TYPE_CLIENT_HELLO, hello_payload, (uint16_t) sizeof( hello_payload ) ) != 0 ) {
		LOGE( "Failed to send handshake CLIENT_HELLO" );
		goto cleanup;
	}

#ifdef _WIN32
	setsockopt( conn->sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*) &rcv_timeout, sizeof( rcv_timeout ) );
#else
	setsockopt( conn->sockfd, SOL_SOCKET, SO_RCVTIMEO, &rcv_timeout, sizeof( rcv_timeout ) );
#endif

	deadline = sqnet_now_sec() + 5;
	while ( sqnet_now_sec() <= deadline ) {
		n = sqnet_recv_packet_fd( conn->sockfd, packet_buf, sizeof( packet_buf ) );
		if ( n <= 0 )
			break;
		if ( !parse_handshake_plain( packet_buf, (size_t) n, &hs_type, &hs_payload, &hs_payload_len ) )
			continue;
		if ( hs_type != HS_TYPE_SERVER_HELLO || hs_payload_len != (uint16_t) ( 8u + 8u + 8u + 32u + HS_PROOF_SIZE ) )
			continue;

		{
			uint64_t echoed_nonce_net;
			uint64_t echoed_nonce;
			uint64_t server_nonce_net;
			uint64_t id_net;
			uint8_t	 expected_proof[HS_PROOF_SIZE];
			uint8_t	 finish_payload[8u + 8u + 8u + HS_PROOF_SIZE];
			uint64_t client_nonce_be;
			uint64_t server_nonce_be;
			uint64_t client_id_be;
			uint32_t new_key[SESSION_KEY_WORDS];
			uint32_t new_secret_key = 0;

			memcpy( &echoed_nonce_net, hs_payload, sizeof( echoed_nonce_net ) );
			echoed_nonce = ntohll( echoed_nonce_net );
			if ( echoed_nonce != client_nonce )
				continue;

			memcpy( &server_nonce_net, hs_payload + 8u, sizeof( server_nonce_net ) );
			server_nonce = ntohll( server_nonce_net );
			memcpy( &id_net, hs_payload + 16u, sizeof( id_net ) );
			client_id = ntohll( id_net );

			if ( sqnet_x25519_shared_secret( client_priv, hs_payload + 24u, shared_secret ) != 0 )
				continue;
			if ( compute_handshake_proof( shared_secret, client_nonce, server_nonce, client_id, HS_ROLE_SERVER, expected_proof ) != 0 )
				continue;
			if ( CRYPTO_memcmp( expected_proof, hs_payload + 56u, HS_PROOF_SIZE ) != 0 )
				continue;

			derive_session_keys( shared_secret, client_nonce, server_nonce, new_key, &new_secret_key );
			conn_set_encryption_keys( conn, new_key, new_secret_key, server_nonce );

			client_nonce_be = htonll( client_nonce );
			server_nonce_be = htonll( server_nonce );
			client_id_be = htonll( client_id );
			memcpy( finish_payload + 0u, &client_nonce_be, sizeof( client_nonce_be ) );
			memcpy( finish_payload + 8u, &server_nonce_be, sizeof( server_nonce_be ) );
			memcpy( finish_payload + 16u, &client_id_be, sizeof( client_id_be ) );
			if ( compute_handshake_proof( shared_secret, client_nonce, server_nonce, client_id, HS_ROLE_CLIENT, finish_payload + 24u ) != 0 ) {
				memset( new_key, 0, sizeof( new_key ) );
				continue;
			}

			if ( send_handshake_plain( conn, &server_addr, HS_TYPE_CLIENT_FINISH, finish_payload, (uint16_t) sizeof( finish_payload ) ) != 0 ) {
				memset( new_key, 0, sizeof( new_key ) );
				continue;
			}

			server_client = (Client*) calloc( 1, sizeof( Client ) );
			if ( !server_client ) {
				memset( new_key, 0, sizeof( new_key ) );
				LOGE( "Memory allocation failed for server client" );
				goto cleanup;
			}

			server_client->addr = server_addr;
			server_client->sockfd = INVALID_SOCK;
			server_client->connected = 1;
			server_client->last_seen = sqnet_now_sec();
			server_client->client_id = client_id;
			server_client->next = conn->clients;
			client_set_encryption_keys( server_client, new_key, new_secret_key, server_nonce );
			conn->clients = server_client;
			memset( new_key, 0, sizeof( new_key ) );
			rc = 0;
			goto cleanup;
		}
	}

	LOGE( "Handshake/key exchange failed or timeout" );
cleanup:
#ifdef _WIN32
	(void) setsockopt( conn->sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*) &rcv_timeout_restore, sizeof( rcv_timeout_restore ) );
#else
	(void) setsockopt( conn->sockfd, SOL_SOCKET, SO_RCVTIMEO, &rcv_timeout_restore, sizeof( rcv_timeout_restore ) );
#endif
	if ( rc != 0 && server_client ) {
		free_client( server_client );
		conn->clients = NULL;
	}
	memset( client_priv, 0, sizeof( client_priv ) );
	memset( client_pub, 0, sizeof( client_pub ) );
	memset( shared_secret, 0, sizeof( shared_secret ) );
	return rc;
}

static int handle_server_handshake( Conn* conn, Client* c, uint8_t hs_type, const uint8_t* hs_payload, uint16_t hs_payload_len, Client** sender )
{
	if ( !conn->is_listener )
		return 0;

	if ( hs_type == HS_TYPE_CLIENT_HELLO && hs_payload_len == (uint16_t) ( 8u + 32u ) ) {
		if ( !c )
			return 0;
		if ( c->keys_ready )
			return 0;

		uint64_t client_nonce_net;
		uint8_t	 server_hello_payload[8u + 8u + 8u + 32u + HS_PROOF_SIZE];
		uint8_t	 server_proof[HS_PROOF_SIZE];

		memcpy( &client_nonce_net, hs_payload, sizeof( client_nonce_net ) );
		uint64_t client_nonce = ntohll( client_nonce_net );
		if ( client_nonce == 0 )
			return 0;

		clear_handshake_state( c );

		memcpy( c->hs_client_pub, hs_payload + 8u, sizeof( c->hs_client_pub ) );
		c->hs_client_nonce = client_nonce;
		uint64_t server_nonce = sqrand();
		if ( server_nonce == 0 )
			server_nonce = 1;
		c->hs_server_nonce = server_nonce;

		if ( sqnet_generate_x25519_keypair( c->hs_server_pub, c->hs_server_priv ) != 0 )
			return 0;
		if ( sqnet_x25519_shared_secret( c->hs_server_priv, c->hs_client_pub, c->hs_shared_secret ) != 0 ) {
			clear_handshake_state( c );
			return 0;
		}

		if ( compute_handshake_proof( c->hs_shared_secret, c->hs_client_nonce, c->hs_server_nonce, c->client_id, HS_ROLE_SERVER, server_proof )
			!= 0 ) {
			clear_handshake_state( c );
			return 0;
		}

		uint64_t client_nonce_be = htonll( c->hs_client_nonce );
		uint64_t server_nonce_be = htonll( c->hs_server_nonce );
		uint64_t client_id_be = htonll( c->client_id );

		memcpy( server_hello_payload + 0u, &client_nonce_be, sizeof( client_nonce_be ) );
		memcpy( server_hello_payload + 8u, &server_nonce_be, sizeof( server_nonce_be ) );
		memcpy( server_hello_payload + 16u, &client_id_be, sizeof( client_id_be ) );
		memcpy( server_hello_payload + 24u, c->hs_server_pub, sizeof( c->hs_server_pub ) );
		memcpy( server_hello_payload + 56u, server_proof, HS_PROOF_SIZE );

		if ( send_handshake_plain( conn, &c->addr, HS_TYPE_SERVER_HELLO, server_hello_payload, (uint16_t) sizeof( server_hello_payload ) ) != 0 ) {
			clear_handshake_state( c );
			return -1;
		}

		c->hs_pending = 1;
		c->last_seen = sqnet_now_sec();
		c->connected = 1;
		if ( sender )
			*sender = c;
		return 0;
	}

	if ( hs_type == HS_TYPE_CLIENT_FINISH && hs_payload_len == (uint16_t) ( 8u + 8u + 8u + HS_PROOF_SIZE ) ) {
		if ( !c || !c->hs_pending )
			return 0;

		uint64_t client_nonce_net, server_nonce_net, client_id_net;
		memcpy( &client_nonce_net, hs_payload + 0u, sizeof( client_nonce_net ) );
		memcpy( &server_nonce_net, hs_payload + 8u, sizeof( server_nonce_net ) );
		memcpy( &client_id_net, hs_payload + 16u, sizeof( client_id_net ) );

		uint64_t client_nonce = ntohll( client_nonce_net );
		uint64_t server_nonce = ntohll( server_nonce_net );
		uint64_t client_id = ntohll( client_id_net );

		if ( client_nonce != c->hs_client_nonce || server_nonce != c->hs_server_nonce || client_id != c->client_id )
			return 0;

		uint8_t expected_proof[HS_PROOF_SIZE];
		if ( compute_handshake_proof( c->hs_shared_secret, c->hs_client_nonce, c->hs_server_nonce, c->client_id, HS_ROLE_CLIENT, expected_proof )
			!= 0 ) {
			clear_handshake_state( c );
			return 0;
		}

		if ( CRYPTO_memcmp( expected_proof, hs_payload + 24u, HS_PROOF_SIZE ) != 0 )
			return 0;

		uint32_t new_key[SESSION_KEY_WORDS];
		uint32_t new_secret_key = 0;
		derive_session_keys( c->hs_shared_secret, c->hs_client_nonce, c->hs_server_nonce, new_key, &new_secret_key );
		client_set_encryption_keys( c, new_key, new_secret_key, c->hs_server_nonce );
		clear_handshake_state( c );
		memset( new_key, 0, sizeof( new_key ) );

		c->last_seen = sqnet_now_sec();
		c->connected = 1;
		if ( sender )
			*sender = c;
		return 0;
	}

	return 0;
}

static int handle_encrypted_packet( Conn* conn, Client* c, uint8_t packet_buf[], int n, void* out_buf, size_t out_size, Client** sender )
{
	if ( (size_t) n < CONN_OVERHEAD_SIZE || !c || !c->keys_ready )
		return 0;

	uint32_t rx_secret = c->secret_key;
	size_t	 payload_len = 0;
	uint64_t packet_iv = 0;

	int dec_rc = try_decrypt_payload( packet_buf, (size_t) n, c->encryption_key, rx_secret, &payload_len, &packet_iv );
	if ( dec_rc <= 0 ) {
		if ( dec_rc < 0 ) {
			if ( conn->is_listener && c )
				conn_remove_client( conn, c );
			return -1;
		}
		return 0;
	}

	if ( replay_seen_or_mark( c, packet_iv ) )
		return 0;

	uint8_t		   ctrl_type = 0;
	const uint8_t* ctrl_payload = NULL;
	uint16_t	   ctrl_payload_len = 0;

	if ( parse_encrypted_control( packet_buf + CONN_PAYLOAD_OFFSET, payload_len, &ctrl_type, &ctrl_payload, &ctrl_payload_len ) ) {
		return 0;
	}

	c->last_seen = sqnet_now_sec();
	c->connected = 1;

	int ret = process_fragmented_payload( conn, c, &c->addr, packet_buf + CONN_PAYLOAD_OFFSET, payload_len, rx_secret, out_buf, out_size, sender );
	if ( ret > 0 ) {
		return ret;
	}

	return 0;
}

static int process_packet( Conn* conn, Client* c, uint8_t packet_buf[], int n, void* buf, size_t size, Client** sender )
{
	uint8_t		   hs_type = 0;
	const uint8_t* hs_payload = NULL;
	uint16_t	   hs_payload_len = 0;

	if ( parse_handshake_plain( packet_buf, (size_t) n, &hs_type, &hs_payload, &hs_payload_len ) ) {
		return handle_server_handshake( conn, c, hs_type, hs_payload, hs_payload_len, sender );
	}

	return handle_encrypted_packet( conn, c, packet_buf, n, buf, size, sender );
}

static int recv_and_process_once( Conn* conn, sock_t fd, Client* c, void* buf, size_t size, Client** sender )
{
	uint8_t packet_buf[SQNET_MAX_PACKET_SIZE];
	int		n = sqnet_recv_packet_fd( fd, packet_buf, sizeof( packet_buf ) );
	if ( n <= 0 ) {
		if ( conn->is_listener && c ) {
			conn_remove_client( conn, c );
		}
		return n;
	}
	return process_packet( conn, c, packet_buf, n, buf, size, sender );
}

int conn_recv( Conn* conn, void* buf, size_t size, Client** sender )
{
	CHECK_INIT();
	if ( !conn || !is_socket_open( conn->sockfd ) || !buf || size == 0 )
		return -1;
	if ( sender )
		*sender = NULL;

	cleanup_stale_assemblies( conn->sockfd, sqnet_now_sec() );

	if ( conn->is_listener ) {
		fd_set		   rfds;
		struct timeval tv = { 0, 0 };
		sock_t		   maxfd = conn->sockfd;
		Client*		   it = conn->clients;

		FD_ZERO( &rfds );
		FD_SET( conn->sockfd, &rfds );
		while ( it ) {
			if ( is_socket_open( it->sockfd ) ) {
				FD_SET( it->sockfd, &rfds );
				if ( it->sockfd > maxfd )
					maxfd = it->sockfd;
			}
			it = it->next;
		}

		int sel = select( (int) maxfd + 1, &rfds, NULL, NULL, &tv );
		if ( sel <= 0 )
			return 0;

		if ( FD_ISSET( conn->sockfd, &rfds ) ) {
			(void) conn_accept_client( conn );
		}

		it = conn->clients;
		while ( it ) {
			Client* next = it->next;
			if ( is_socket_open( it->sockfd ) && FD_ISSET( it->sockfd, &rfds ) ) {
				int rc = recv_and_process_once( conn, it->sockfd, it, buf, size, sender );
				if ( rc > 0 )
					return rc;
				if ( rc == 0 ) {
				} else if ( rc < 0 ) {
				}
			}
			it = next;
		}
		return 0;
	} else {
		Client* c = conn->clients;
		sock_t	in_fd = conn->sockfd;

		return recv_and_process_once( conn, in_fd, c, buf, size, sender );
	}
}

int conn_send( Conn* conn, const void* data, size_t len, Client* client )
{
	CHECK_INIT();
	if ( !conn || !is_socket_open( conn->sockfd ) || !data || len == 0 || !client )
		return -1;
	if ( !client->keys_ready ) {
		LOGE( "Client keys not ready yet (handshake not completed)" );
		return -1;
	}

	if ( send_fragmented_with_keys( conn, data, len, client->encryption_key, client->secret_key, &client->addr ) < 0 ) {
		LOGI( "Failed to send to client, removing client socket" );
		conn_remove_client( conn, client );
		return -1;
	}

	client->last_seen = sqnet_now_sec();
	return (int) len;
}
