#include "relay_client.h"

#include "sqNet/sqNet.h"
#include "sqNet/sqNet_internal.h"
#include "common.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#ifndef _WIN32
# include <sys/stat.h>
#endif

#define E2E_PLAIN_SIZE ( 2u + MAX_TEXT + 1u )
#define E2E_REPLAY_CACHE 32
#define RELAY_MAX_PENDING_MSGS 64

typedef struct PendingMsg
{
	char			   text[MAX_TEXT + 1];
	struct PendingMsg* next;
} PendingMsg;

typedef struct ReplayItem
{
	uint64_t iv;
	uint64_t ts;
} ReplayItem;

typedef struct E2EState
{
	int		established;
	int		awaiting_reply;
	int		awaiting_ack;
	int		sent_hello;
	int		have_peer_pub;
	uint8_t peer_pub[32];

	int		have_eph;
	uint8_t eph_pub[32];
	uint8_t eph_priv[32];

	int		have_peer_eph_pub;
	uint8_t peer_eph_pub[32];

	uint64_t my_nonce;
	uint64_t peer_nonce;
	uint32_t session_key[SESSION_KEY_WORDS];
	uint32_t session_secret;

	ReplayItem replay[E2E_REPLAY_CACHE];
	unsigned   replay_count;
	unsigned   replay_pos;

	PendingMsg* pend_head;
	PendingMsg* pend_tail;
	int			pend_count;
} E2EState;

struct RelayMsg
{
	char			 from[MAX_NICK + 1];
	char			 text[MAX_TEXT + 1];
	struct RelayMsg* next;
};

struct RelayChat
{
	char			  handle[MAX_NICK + 1];
	char			  id[RELAY_PUBKEY_HEX_LEN + 1];
	char			  display_name[MAX_NICK + 1];
	RelayMsg*		  head;
	RelayMsg*		  tail;
	int				  unread;
	int				  msg_count;
	E2EState		  e2e;
	struct RelayChat* next;
};

struct RelayClient
{
	Conn			conn;
	volatile int	running;
	volatile int	connected;
	char			my_handle[MAX_NICK + 1];
	char			my_nick[MAX_NICK + 1];
	char			my_id[RELAY_PUBKEY_HEX_LEN + 1];
	uint8_t			id_pub[32];
	uint8_t			id_priv[32];
	char			status[256];
	RelayChat*		chats;
	RelayChat*		active;
	pthread_mutex_t lock;
	pthread_t		net_thread;
	int				net_thread_started;
	char			storage_dir[256];
	RelayCallbacks	callbacks;
	void*			cb_user;
};

static int starts_with( const char* s, const char* prefix )
{
	return strncmp( s, prefix, strlen( prefix ) ) == 0;
}

static void trim_eol( char* s )
{
	size_t n = strlen( s );
	while ( n > 0 && ( s[n - 1] == '\n' || s[n - 1] == '\r' ) )
		s[--n] = '\0';
}

static void ltrim( char** s )
{
	while ( **s == ' ' || **s == '\t' )
		( *s )++;
}

static char* next_token( char** p )
{
	if ( !p || !*p )
		return NULL;

	char* s = *p;
	while ( *s == ' ' || *s == '\t' )
		s++;

	if ( *s == '\0' ) {
		*p = s;
		return NULL;
	}

	char* e = s;
	while ( *e && *e != ' ' && *e != '\t' )
		e++;

	if ( *e ) {
		*e = '\0';
		*p = e + 1;
	} else {
		*p = e;
	}

	return s;
}

static int parse_tokens( char* line, const char* prefix, char** out, size_t count )
{
	char* p = line + strlen( prefix );
	for ( size_t i = 0; i < count; i++ ) {
		out[i] = next_token( &p );
		if ( !out[i] )
			return 0;
	}
	return 1;
}

static void set_status_locked( RelayClient* c, const char* fmt, ... )
{
	va_list ap;
	va_start( ap, fmt );
	vsnprintf( c->status, sizeof( c->status ), fmt, ap );
	va_end( ap );

	if ( c->callbacks.on_status )
		c->callbacks.on_status( c, c->status, c->cb_user );
}

static void hex_encode( const uint8_t* in, size_t len, char* out, size_t outcap )
{
	static const char hex[] = "0123456789abcdef";

	if ( outcap < len * 2 + 1 ) {
		if ( outcap )
			out[0] = '\0';
		return;
	}

	for ( size_t i = 0; i < len; i++ ) {
		out[i * 2] = hex[in[i] >> 4];
		out[i * 2 + 1] = hex[in[i] & 0x0F];
	}

	out[len * 2] = '\0';
}

static int hex_nibble( char c )
{
	if ( c >= '0' && c <= '9' )
		return c - '0';
	if ( c >= 'a' && c <= 'f' )
		return c - 'a' + 10;
	if ( c >= 'A' && c <= 'F' )
		return c - 'A' + 10;
	return -1;
}

static int hex_decode( const char* in, uint8_t* out, size_t outcap )
{
	size_t len = strlen( in );
	if ( ( len & 1u ) != 0 )
		return 0;

	size_t bytes = len / 2;
	if ( bytes > outcap )
		return 0;

	for ( size_t i = 0; i < bytes; i++ ) {
		int hi = hex_nibble( in[i * 2] );
		int lo = hex_nibble( in[i * 2 + 1] );
		if ( hi < 0 || lo < 0 )
			return 0;
		out[i] = (uint8_t) ( ( hi << 4 ) | lo );
	}

	return 1;
}

static int parse_u64_hex( const char* s, uint64_t* out )
{
	if ( !s || !*s || !out )
		return 0;

	char*			   end = NULL;
	unsigned long long v = strtoull( s, &end, 16 );
	if ( !end || *end != '\0' )
		return 0;

	*out = (uint64_t) v;
	return 1;
}

static int random_bytes( void* out, size_t len )
{
	return sqrand_bytes( (unsigned char*) out, (int) len ) == 1;
}

static int valid_peer_id( const char* peer_id )
{
	if ( !peer_id || strlen( peer_id ) != RELAY_PUBKEY_HEX_LEN )
		return 0;

	for ( size_t i = 0; i < RELAY_PUBKEY_HEX_LEN; i++ ) {
		if ( hex_nibble( peer_id[i] ) < 0 )
			return 0;
	}

	return 1;
}

static int valid_name_token( const char* s, size_t max_len )
{
	size_t len = s ? strlen( s ) : 0;
	if ( len < 3 || len > max_len )
		return 0;

	for ( size_t i = 0; i < len; i++ ) {
		unsigned char c = (unsigned char) s[i];
		if ( !( ( c >= 'a' && c <= 'z' ) || ( c >= 'A' && c <= 'Z' ) || ( c >= '0' && c <= '9' ) || c == '_' || c == '-' ) )
			return 0;
	}

	return 1;
}

static int valid_handle( const char* handle )
{
	return valid_name_token( handle, MAX_NICK );
}

static int valid_display_name( const char* display_name )
{
	return valid_name_token( display_name, MAX_NICK );
}

static void short_peer_id( const char* peer_id, char out[18] )
{
	if ( !valid_peer_id( peer_id ) ) {
		snprintf( out, 18, "unknown peer" );
		return;
	}

	snprintf( out, 18, "%.8s...%.8s", peer_id, peer_id + RELAY_PUBKEY_HEX_LEN - 8 );
}

static uint64_t pubkey_id64( const uint8_t pub[32] )
{
	uint64_t h = 1469598103934665603ULL;
	for ( size_t i = 0; i < 32; i++ ) {
		h ^= pub[i];
		h *= 1099511628211ULL;
	}
	return h;
}

static FILE* open_private_file( const char* path, const char* mode )
{
#ifndef _WIN32
	int flags = 0;

	if ( strcmp( mode, "wb" ) == 0 )
		flags = O_WRONLY | O_CREAT | O_TRUNC;
	else if ( strcmp( mode, "a" ) == 0 )
		flags = O_WRONLY | O_CREAT | O_APPEND;
	else
		return fopen( path, mode );

	int fd = open( path, flags, 0600 );
	if ( fd < 0 )
		return NULL;

	FILE* f = fdopen( fd, mode );
	if ( !f )
		close( fd );
	return f;
#else
	return fopen( path, mode );
#endif
}

static void e2e_clear_transient_locked( E2EState* e )
{
	if ( !e )
		return;

	e->established = 0;
	e->awaiting_reply = 0;
	e->awaiting_ack = 0;
	e->sent_hello = 0;
	e->have_eph = 0;
	e->have_peer_eph_pub = 0;
	e->my_nonce = 0;
	e->peer_nonce = 0;

	memset( e->eph_pub, 0, sizeof( e->eph_pub ) );
	memset( e->eph_priv, 0, sizeof( e->eph_priv ) );
	memset( e->peer_eph_pub, 0, sizeof( e->peer_eph_pub ) );
	memset( e->session_key, 0, sizeof( e->session_key ) );
	e->session_secret = 0;

	memset( e->replay, 0, sizeof( e->replay ) );
	e->replay_count = 0;
	e->replay_pos = 0;
}

static int e2e_make_ephemeral_locked( E2EState* e )
{
	if ( e->have_eph )
		return 1;

	if ( sqnet_generate_x25519_keypair( e->eph_pub, e->eph_priv ) != 0 )
		return 0;

	e->have_eph = 1;
	return 1;
}

static int e2e_seen_replay_locked( const E2EState* e, uint64_t iv, uint64_t ts )
{
	for ( unsigned i = 0; i < e->replay_count; i++ ) {
		const ReplayItem* r = &e->replay[i];
		if ( r->iv == iv && r->ts == ts )
			return 1;
	}
	return 0;
}

static void e2e_record_replay_locked( E2EState* e, uint64_t iv, uint64_t ts )
{
	e->replay[e->replay_pos].iv = iv;
	e->replay[e->replay_pos].ts = ts;

	e->replay_pos = ( e->replay_pos + 1 ) % E2E_REPLAY_CACHE;
	if ( e->replay_count < E2E_REPLAY_CACHE )
		e->replay_count++;
}

static void make_identity_path( const RelayClient* c, char* out, size_t outcap )
{
	if ( c->storage_dir[0] )
		snprintf( out, outcap, "%s/.relay_identity.bin", c->storage_dir );
	else
		snprintf( out, outcap, ".relay_identity.bin" );
}

static int load_or_create_identity( const RelayClient* c, uint8_t pub[32], uint8_t priv[32] )
{
	char path[256];
	make_identity_path( c, path, sizeof( path ) );

	FILE* f = fopen( path, "rb" );
	if ( f ) {
		int ok = ( fread( pub, 1, 32, f ) == 32 ) && ( fread( priv, 1, 32, f ) == 32 );
#ifndef _WIN32
		fchmod( fileno( f ), 0600 );
#endif
		fclose( f );
		if ( ok )
			return 1;
	}

	if ( sqnet_generate_x25519_keypair( pub, priv ) != 0 )
		return 0;

	f = open_private_file( path, "wb" );
	if ( f ) {
		fwrite( pub, 1, 32, f );
		fwrite( priv, 1, 32, f );
		fflush( f );
#ifndef _WIN32
		fchmod( fileno( f ), 0600 );
#endif
		fclose( f );
	}

	return 1;
}

static void chat_set_display_name( RelayChat* chat, const char* nick )
{
	if ( !chat )
		return;

	if ( nick && *nick ) {
		snprintf( chat->display_name, sizeof( chat->display_name ), "%s", nick );
		return;
	}

	if ( chat->handle[0] )
		snprintf( chat->display_name, sizeof( chat->display_name ), "%s", chat->handle );
	else
		short_peer_id( chat->id, chat->display_name );
}

static RelayChat* chat_find( RelayClient* c, const char* handle, RelayChat** prev_out )
{
	RelayChat* prev = NULL;

	for ( RelayChat* it = c->chats; it; it = it->next ) {
		if ( strcmp( it->handle, handle ) == 0 ) {
			if ( prev_out )
				*prev_out = prev;
			return it;
		}
		prev = it;
	}

	if ( prev_out )
		*prev_out = NULL;
	return NULL;
}

static RelayChat* chat_get_or_create( RelayClient* c, const char* handle, const char* display_name, const char* peer_id )
{
	RelayChat* chat = chat_find( c, handle, NULL );
	if ( chat ) {
		if ( display_name && *display_name )
			chat_set_display_name( chat, display_name );
		if ( peer_id && *peer_id && valid_peer_id( peer_id ) )
			snprintf( chat->id, sizeof( chat->id ), "%s", peer_id );
		if ( valid_peer_id( chat->id ) && hex_decode( chat->id, chat->e2e.peer_pub, 32 ) )
			chat->e2e.have_peer_pub = 1;
		return chat;
	}

	chat = (RelayChat*) calloc( 1, sizeof( *chat ) );
	if ( !chat )
		return NULL;

	snprintf( chat->handle, sizeof( chat->handle ), "%s", handle );
	if ( peer_id && *peer_id && valid_peer_id( peer_id ) )
		snprintf( chat->id, sizeof( chat->id ), "%s", peer_id );
	chat_set_display_name( chat, display_name );

	if ( valid_peer_id( chat->id ) && hex_decode( chat->id, chat->e2e.peer_pub, 32 ) )
		chat->e2e.have_peer_pub = 1;

	chat->next = c->chats;
	c->chats = chat;
	return chat;
}

static void chat_move_front( RelayClient* c, RelayChat* chat )
{
	if ( !chat || c->chats == chat )
		return;

	RelayChat** pp = &c->chats;
	while ( *pp && *pp != chat )
		pp = &( *pp )->next;

	if ( !*pp )
		return;

	*pp = chat->next;
	chat->next = c->chats;
	c->chats = chat;
}

static void chat_append_msg( RelayChat* chat, const char* from, const char* text )
{
	RelayMsg* msg = (RelayMsg*) calloc( 1, sizeof( *msg ) );
	if ( !msg )
		return;

	snprintf( msg->from, sizeof( msg->from ), "%s", from );
	snprintf( msg->text, sizeof( msg->text ), "%s", text );

	if ( !chat->head )
		chat->head = chat->tail = msg;
	else {
		chat->tail->next = msg;
		chat->tail = msg;
	}

	chat->msg_count++;
}

static void free_pending( PendingMsg* p )
{
	while ( p ) {
		PendingMsg* next = p->next;
		free( p );
		p = next;
	}
}

static void free_chats( RelayClient* c )
{
	for ( RelayChat* chat = c->chats; chat; ) {
		for ( RelayMsg* msg = chat->head; msg; ) {
			RelayMsg* next = msg->next;
			free( msg );
			msg = next;
		}

		free_pending( chat->e2e.pend_head );

		RelayChat* next = chat->next;
		free( chat );
		chat = next;
	}

	c->chats = NULL;
	c->active = NULL;
}

static void send_line( RelayClient* c, const char* line )
{
	Client* srv = conn_clients( &c->conn );
	if ( srv )
		conn_send( &c->conn, (uint8_t*) line, strlen( line ), srv );
}

static void send_linef( RelayClient* c, const char* fmt, ... )
{
	char	line[MAX_LINE];
	va_list ap;
	va_start( ap, fmt );
	vsnprintf( line, sizeof( line ), fmt, ap );
	va_end( ap );
	send_line( c, line );
}

static void e2e_set_established_locked( RelayClient* c, RelayChat* chat, int established )
{
	int changed = ( chat->e2e.established != established );
	chat->e2e.established = established;
	if ( changed && c->callbacks.on_e2e )
		c->callbacks.on_e2e( c, chat->display_name, established, c->cb_user );
}

static int e2e_prepare_session( RelayClient* c, RelayChat* chat, const uint8_t peer_id_pub[32], const uint8_t peer_eph_pub[32],
	uint64_t initiator_nonce, uint64_t responder_nonce )
{
	uint8_t	 shared_id[32];
	uint8_t	 shared_eph[32];
	uint32_t key_id[SESSION_KEY_WORDS];
	uint32_t key_eph[SESSION_KEY_WORDS];
	uint32_t sec_id = 0;
	uint32_t sec_eph = 0;

	if ( sqnet_x25519_shared_secret( c->id_priv, peer_id_pub, shared_id ) != 0 )
		return 0;

	derive_session_keys( shared_id, initiator_nonce, responder_nonce, key_id, &sec_id );

	if ( !peer_eph_pub || !chat->e2e.have_eph )
		return 0;

	if ( sqnet_x25519_shared_secret( chat->e2e.eph_priv, peer_eph_pub, shared_eph ) != 0 )
		return 0;

	derive_session_keys( shared_eph, initiator_nonce, responder_nonce, key_eph, &sec_eph );

	for ( size_t i = 0; i < SESSION_KEY_WORDS; i++ )
		chat->e2e.session_key[i] = key_id[i] ^ key_eph[i];

	chat->e2e.session_secret = sec_id ^ sec_eph;
	return 1;
}

static void e2e_queue_pending_locked( RelayChat* chat, const char* text )
{
	while ( chat->e2e.pend_count >= RELAY_MAX_PENDING_MSGS && chat->e2e.pend_head ) {
		PendingMsg* old = chat->e2e.pend_head;
		chat->e2e.pend_head = old->next;
		if ( !chat->e2e.pend_head )
			chat->e2e.pend_tail = NULL;
		free( old );
		chat->e2e.pend_count--;
	}

	PendingMsg* p = (PendingMsg*) calloc( 1, sizeof( *p ) );
	if ( !p )
		return;

	snprintf( p->text, sizeof( p->text ), "%s", text );

	if ( !chat->e2e.pend_head )
		chat->e2e.pend_head = chat->e2e.pend_tail = p;
	else {
		chat->e2e.pend_tail->next = p;
		chat->e2e.pend_tail = p;
	}

	chat->e2e.pend_count++;
}

static void e2e_send_fail( RelayClient* c, const char* target, const char* reason )
{
	send_linef( c, "E2E_FAIL %s %s", target, reason );
}

static int e2e_send_encrypted_locked( RelayClient* c, RelayChat* chat, const char* text )
{
	uint8_t	 plain[E2E_PLAIN_SIZE];
	uint8_t	 tag[CONN_TAG_SIZE];
	uint64_t iv = 0;
	uint64_t ts = now_ms();

	memset( plain, 0, sizeof( plain ) );

	size_t len = strlen( text );
	if ( len > MAX_TEXT )
		len = MAX_TEXT;

	plain[0] = (uint8_t) ( ( len >> 8 ) & 0xFF );
	plain[1] = (uint8_t) ( len & 0xFF );
	memcpy( plain + 2, text, len );

	random_bytes( &iv, sizeof( iv ) );

	if ( openssl_payload_pass( plain, sizeof( plain ), chat->e2e.session_key, chat->e2e.session_secret, iv, ts, tag, 1 ) != 0 )
		return 0;

	char cipher_hex[E2E_PLAIN_SIZE * 2 + 1];
	char tag_hex[CONN_TAG_SIZE * 2 + 1];
	char iv_hex[17];
	char ts_hex[17];

	hex_encode( plain, sizeof( plain ), cipher_hex, sizeof( cipher_hex ) );
	hex_encode( tag, sizeof( tag ), tag_hex, sizeof( tag_hex ) );
	snprintf( iv_hex, sizeof( iv_hex ), "%016llx", (unsigned long long) iv );
	snprintf( ts_hex, sizeof( ts_hex ), "%016llx", (unsigned long long) ts );

	send_linef( c, "E2E_MSG %s %s %s %s %s", chat->handle, iv_hex, ts_hex, tag_hex, cipher_hex );

	return 1;
}

static void e2e_flush_pending_locked( RelayClient* c, RelayChat* chat )
{
	while ( chat->e2e.established && chat->e2e.pend_head ) {
		PendingMsg* p = chat->e2e.pend_head;
		chat->e2e.pend_head = p->next;
		if ( !chat->e2e.pend_head )
			chat->e2e.pend_tail = NULL;

		char text[MAX_TEXT + 1];
		snprintf( text, sizeof( text ), "%s", p->text );
		free( p );

		chat->e2e.pend_count--;
		if ( !e2e_send_encrypted_locked( c, chat, text ) ) {
			set_status_locked( c, "failed to encrypt/send to %s", chat->display_name );
			return;
		}
	}
}

static void e2e_start_handshake_locked( RelayClient* c, RelayChat* chat )
{
	if ( chat->e2e.sent_hello )
		return;

	if ( chat->e2e.my_nonce == 0 )
		random_bytes( &chat->e2e.my_nonce, sizeof( chat->e2e.my_nonce ) );

	if ( !e2e_make_ephemeral_locked( &chat->e2e ) ) {
		set_status_locked( c, "E2E ephemeral key gen failed for %s", chat->display_name );
		return;
	}

	char pub_hex[65];
	char eph_hex[65];
	char nonce_hex[17];

	hex_encode( c->id_pub, 32, pub_hex, sizeof( pub_hex ) );
	hex_encode( chat->e2e.eph_pub, 32, eph_hex, sizeof( eph_hex ) );
	snprintf( nonce_hex, sizeof( nonce_hex ), "%016llx", (unsigned long long) chat->e2e.my_nonce );

	send_linef( c, "E2E_HELLO %s %s %s %s", chat->handle, nonce_hex, pub_hex, eph_hex );

	chat->e2e.sent_hello = 1;
	chat->e2e.awaiting_reply = 1;
	set_status_locked( c, "E2E handshake started with %s", chat->display_name );
}

static void e2e_handle_hello( RelayClient* c, char* line )
{
	char* tok[7];
	if ( !parse_tokens( line, "E2E_HELLO ", tok, 7 ) )
		return;

	char* from_handle = tok[0];
	char* from_nick = tok[1];
	char* from_id = tok[2];
	char* nonce_hex = tok[4];
	char* pub_hex = tok[5];
	char* eph_hex = tok[6];

	uint64_t peer_nonce = 0;
	if ( !parse_u64_hex( nonce_hex, &peer_nonce ) )
		return;

	uint8_t peer_pub[32];
	uint8_t peer_eph_pub[32];

	if ( !hex_decode( pub_hex, peer_pub, 32 ) )
		return;
	if ( !hex_decode( eph_hex, peer_eph_pub, 32 ) )
		return;

	RelayChat* chat = chat_get_or_create( c, from_handle, from_nick, from_id );
	if ( !chat )
		return;

	chat_move_front( c, chat );

	if ( chat->e2e.have_peer_pub && memcmp( chat->e2e.peer_pub, peer_pub, 32 ) != 0 ) {
		set_status_locked( c, "E2E key mismatch for %s", chat->display_name );
		e2e_send_fail( c, from_handle, "key_changed" );
		e2e_clear_transient_locked( &chat->e2e );
		return;
	}

	if ( !chat->e2e.have_peer_pub ) {
		memcpy( chat->e2e.peer_pub, peer_pub, 32 );
		chat->e2e.have_peer_pub = 1;
	}

	if ( chat->e2e.have_peer_eph_pub && memcmp( chat->e2e.peer_eph_pub, peer_eph_pub, 32 ) != 0 ) {
		set_status_locked( c, "E2E ephemeral key mismatch for %s", chat->display_name );
		e2e_send_fail( c, from_handle, "key_changed" );
		e2e_clear_transient_locked( &chat->e2e );
		return;
	}

	if ( !chat->e2e.have_peer_eph_pub ) {
		memcpy( chat->e2e.peer_eph_pub, peer_eph_pub, 32 );
		chat->e2e.have_peer_eph_pub = 1;
	}

	chat->e2e.peer_nonce = peer_nonce;

	if ( chat->e2e.my_nonce == 0 )
		random_bytes( &chat->e2e.my_nonce, sizeof( chat->e2e.my_nonce ) );

	if ( !e2e_make_ephemeral_locked( &chat->e2e ) ) {
		set_status_locked( c, "E2E eph setup failed for %s", chat->display_name );
		e2e_send_fail( c, from_handle, "setup_failed" );
		e2e_clear_transient_locked( &chat->e2e );
		return;
	}

	if ( !e2e_prepare_session( c, chat, peer_pub, peer_eph_pub, peer_nonce, chat->e2e.my_nonce ) ) {
		set_status_locked( c, "E2E session setup failed for %s", chat->display_name );
		e2e_send_fail( c, from_handle, "setup_failed" );
		e2e_clear_transient_locked( &chat->e2e );
		return;
	}

	uint8_t proof[32];
	if ( compute_handshake_proof( (const uint8_t*) chat->e2e.session_key, peer_nonce, chat->e2e.my_nonce, pubkey_id64( peer_pub ), 1, proof ) != 0 ) {
		set_status_locked( c, "E2E proof creation failed for %s", chat->display_name );
		e2e_send_fail( c, from_handle, "proof_failed" );
		e2e_clear_transient_locked( &chat->e2e );
		return;
	}

	char nonce2_hex[17];
	char pub2_hex[65];
	char eph2_hex[65];
	char proof_hex[65];

	snprintf( nonce2_hex, sizeof( nonce2_hex ), "%016llx", (unsigned long long) chat->e2e.my_nonce );
	hex_encode( c->id_pub, 32, pub2_hex, sizeof( pub2_hex ) );
	hex_encode( chat->e2e.eph_pub, 32, eph2_hex, sizeof( eph2_hex ) );
	hex_encode( proof, 32, proof_hex, sizeof( proof_hex ) );

	send_linef( c, "E2E_REPLY %s %s %s %s %s %s", from_handle, nonce_hex, nonce2_hex, pub2_hex, proof_hex, eph2_hex );

	chat->e2e.awaiting_ack = 1;
	set_status_locked( c, "E2E reply sent to %s", chat->display_name );
}

static void e2e_handle_reply( RelayClient* c, char* line )
{
	char* tok[9];
	if ( !parse_tokens( line, "E2E_REPLY ", tok, 9 ) )
		return;

	char* from_handle = tok[0];
	char* from_nick = tok[1];
	char* from_id = tok[2];
	char* initiator_nonce_hex = tok[4];
	char* responder_nonce_hex = tok[5];
	char* pub_hex = tok[6];
	char* proof_hex = tok[7];
	char* eph_hex = tok[8];

	uint64_t initiator_nonce = 0;
	uint64_t responder_nonce = 0;

	if ( !parse_u64_hex( initiator_nonce_hex, &initiator_nonce ) )
		return;
	if ( !parse_u64_hex( responder_nonce_hex, &responder_nonce ) )
		return;

	uint8_t peer_pub[32];
	uint8_t proof[32];
	uint8_t peer_eph_pub[32];

	if ( !hex_decode( pub_hex, peer_pub, 32 ) )
		return;
	if ( !hex_decode( proof_hex, proof, 32 ) )
		return;
	if ( !hex_decode( eph_hex, peer_eph_pub, 32 ) )
		return;

	RelayChat* chat = chat_get_or_create( c, from_handle, from_nick, from_id );
	if ( !chat )
		return;

	chat_move_front( c, chat );

	if ( chat->e2e.my_nonce == 0 || !chat->e2e.awaiting_reply ) {
		set_status_locked( c, "unexpected E2E reply from %s", chat->display_name );
		return;
	}

	if ( initiator_nonce != chat->e2e.my_nonce ) {
		set_status_locked( c, "E2E nonce mismatch from %s", chat->display_name );
		return;
	}

	if ( chat->e2e.have_peer_pub && memcmp( chat->e2e.peer_pub, peer_pub, 32 ) != 0 ) {
		set_status_locked( c, "E2E key mismatch for %s", chat->display_name );
		e2e_send_fail( c, from_handle, "key_changed" );
		e2e_clear_transient_locked( &chat->e2e );
		return;
	}

	if ( !chat->e2e.have_peer_pub ) {
		memcpy( chat->e2e.peer_pub, peer_pub, 32 );
		chat->e2e.have_peer_pub = 1;
	}

	if ( chat->e2e.have_peer_eph_pub && memcmp( chat->e2e.peer_eph_pub, peer_eph_pub, 32 ) != 0 ) {
		set_status_locked( c, "E2E ephemeral key mismatch for %s", chat->display_name );
		e2e_send_fail( c, from_handle, "key_changed" );
		e2e_clear_transient_locked( &chat->e2e );
		return;
	}

	if ( !chat->e2e.have_peer_eph_pub ) {
		memcpy( chat->e2e.peer_eph_pub, peer_eph_pub, 32 );
		chat->e2e.have_peer_eph_pub = 1;
	}

	if ( !e2e_prepare_session( c, chat, peer_pub, peer_eph_pub, initiator_nonce, responder_nonce ) ) {
		set_status_locked( c, "E2E session derivation failed for %s", chat->display_name );
		e2e_send_fail( c, from_handle, "setup_failed" );
		e2e_clear_transient_locked( &chat->e2e );
		return;
	}

	uint8_t expected[32];
	if ( compute_handshake_proof( (const uint8_t*) chat->e2e.session_key, initiator_nonce, responder_nonce, pubkey_id64( c->id_pub ), 1, expected )
		!= 0 ) {
		set_status_locked( c, "E2E proof check failed for %s", chat->display_name );
		e2e_clear_transient_locked( &chat->e2e );
		return;
	}

	if ( memcmp( expected, proof, 32 ) != 0 ) {
		set_status_locked( c, "bad E2E proof from %s", chat->display_name );
		e2e_send_fail( c, from_handle, "bad_proof" );
		e2e_clear_transient_locked( &chat->e2e );
		return;
	}

	chat->e2e.peer_nonce = responder_nonce;
	chat->e2e.awaiting_reply = 0;
	chat->e2e.awaiting_ack = 0;
	chat->e2e.sent_hello = 1;

	e2e_set_established_locked( c, chat, 1 );
	set_status_locked( c, "E2E established with %s", chat->display_name );

	uint8_t ack_proof[32];
	if ( compute_handshake_proof( (const uint8_t*) chat->e2e.session_key, initiator_nonce, responder_nonce, pubkey_id64( c->id_pub ), 2, ack_proof )
		!= 0 ) {
		set_status_locked( c, "E2E ack proof failed for %s", chat->display_name );
		return;
	}

	char proof2_hex[65];
	hex_encode( ack_proof, 32, proof2_hex, sizeof( proof2_hex ) );

	send_linef( c, "E2E_ACK %s %s %s %s", from_handle, initiator_nonce_hex, responder_nonce_hex, proof2_hex );

	e2e_flush_pending_locked( c, chat );
}

static void e2e_handle_ack( RelayClient* c, char* line )
{
	char* tok[7];
	if ( !parse_tokens( line, "E2E_ACK ", tok, 7 ) )
		return;

	char* from_handle = tok[0];
	char* from_nick = tok[1];
	char* from_id = tok[2];
	char* initiator_nonce_hex = tok[4];
	char* responder_nonce_hex = tok[5];
	char* proof_hex = tok[6];

	uint64_t initiator_nonce = 0;
	uint64_t responder_nonce = 0;

	if ( !parse_u64_hex( initiator_nonce_hex, &initiator_nonce ) )
		return;
	if ( !parse_u64_hex( responder_nonce_hex, &responder_nonce ) )
		return;

	uint8_t proof[32];
	if ( !hex_decode( proof_hex, proof, 32 ) )
		return;

	RelayChat* chat = chat_get_or_create( c, from_handle, from_nick, from_id );
	if ( !chat )
		return;

	chat_move_front( c, chat );

	if ( !chat->e2e.awaiting_ack ) {
		set_status_locked( c, "unexpected E2E ack from %s", chat->display_name );
		return;
	}

	if ( initiator_nonce != chat->e2e.my_nonce || responder_nonce != chat->e2e.peer_nonce ) {
		set_status_locked( c, "E2E ack nonce mismatch from %s", chat->display_name );
		return;
	}

	uint8_t expected[32];
	if ( compute_handshake_proof(
			 (const uint8_t*) chat->e2e.session_key, initiator_nonce, responder_nonce, pubkey_id64( chat->e2e.peer_pub ), 2, expected )
		!= 0 ) {
		set_status_locked( c, "E2E ack verify failed for %s", chat->display_name );
		return;
	}

	if ( memcmp( expected, proof, 32 ) != 0 ) {
		set_status_locked( c, "bad E2E ack from %s", chat->display_name );
		return;
	}

	chat->e2e.awaiting_ack = 0;
	chat->e2e.awaiting_reply = 0;
	chat->e2e.sent_hello = 1;

	e2e_set_established_locked( c, chat, 1 );
	set_status_locked( c, "E2E established with %s", chat->display_name );
	e2e_flush_pending_locked( c, chat );
}

static void e2e_handle_msg( RelayClient* c, char* line )
{
	char* tok[8];
	if ( !parse_tokens( line, "E2E_MSG ", tok, 8 ) )
		return;

	char* from_handle = tok[0];
	char* from_nick = tok[1];
	char* from_id = tok[2];
	char* iv_hex = tok[4];
	char* ts_hex = tok[5];
	char* tag_hex = tok[6];
	char* cipher_hex = tok[7];

	uint64_t iv = 0;
	uint64_t ts = 0;

	if ( !parse_u64_hex( iv_hex, &iv ) )
		return;
	if ( !parse_u64_hex( ts_hex, &ts ) )
		return;

	uint8_t tag[CONN_TAG_SIZE];
	uint8_t plain[E2E_PLAIN_SIZE];

	if ( !hex_decode( tag_hex, tag, sizeof( tag ) ) )
		return;
	if ( !hex_decode( cipher_hex, plain, sizeof( plain ) ) )
		return;

	RelayChat* chat = chat_get_or_create( c, from_handle, from_nick, from_id );
	if ( !chat )
		return;

	chat_move_front( c, chat );

	const int allow_early = ( !chat->e2e.established && chat->e2e.awaiting_ack );
	if ( !chat->e2e.established && !allow_early ) {
		set_status_locked( c, "received encrypted message from %s before session", chat->display_name );
		return;
	}

	if ( e2e_seen_replay_locked( &chat->e2e, iv, ts ) ) {
		set_status_locked( c, "replay rejected from %s", chat->display_name );
		return;
	}

	if ( openssl_payload_pass( plain, sizeof( plain ), chat->e2e.session_key, chat->e2e.session_secret, iv, ts, tag, 0 ) != 0 ) {
		set_status_locked( c, "decrypt failed from %s", chat->display_name );
		return;
	}

	e2e_record_replay_locked( &chat->e2e, iv, ts );

	if ( allow_early ) {
		e2e_set_established_locked( c, chat, 1 );
		e2e_flush_pending_locked( c, chat );
	}

	uint16_t len = (uint16_t) ( ( plain[0] << 8 ) | plain[1] );
	if ( len > MAX_TEXT )
		len = MAX_TEXT;

	char text[MAX_TEXT + 1];
	memcpy( text, plain + 2, len );
	text[len] = '\0';

	chat_append_msg( chat, chat->display_name, text );
	if ( c->active != chat )
		chat->unread++;

	set_status_locked( c, "message from %s", chat->display_name );
	if ( c->callbacks.on_message )
		c->callbacks.on_message( c, chat->display_name, text, c->cb_user );
}

static void e2e_handle_fail( RelayClient* c, char* line )
{
	char* tok[5];
	if ( !parse_tokens( line, "E2E_FAIL ", tok, 5 ) )
		return;

	char* from_handle = tok[0];
	char* from_nick = tok[1];
	char* from_id = tok[2];
	char* reason = tok[4];

	RelayChat* chat = chat_get_or_create( c, from_handle, from_nick, from_id );
	if ( chat ) {
		chat->e2e.awaiting_reply = 0;
		chat->e2e.awaiting_ack = 0;
		e2e_set_established_locked( c, chat, 0 );
		e2e_clear_transient_locked( &chat->e2e );
	}

	set_status_locked( c, "E2E failed from %s: %s", chat ? chat->display_name : from_id, reason );
}

static void handle_server_line( RelayClient* c, char* line )
{
	if ( starts_with( line, "E2E_HELLO " ) ) {
		e2e_handle_hello( c, line );
		return;
	}

	if ( starts_with( line, "E2E_REPLY " ) ) {
		e2e_handle_reply( c, line );
		return;
	}

	if ( starts_with( line, "E2E_ACK " ) ) {
		e2e_handle_ack( c, line );
		return;
	}

	if ( starts_with( line, "E2E_MSG " ) ) {
		e2e_handle_msg( c, line );
		return;
	}

	if ( starts_with( line, "E2E_FAIL " ) ) {
		e2e_handle_fail( c, line );
		return;
	}

	if ( starts_with( line, "IN " ) ) {
		char* p = line + 3;
		char* from_handle = next_token( &p );
		char* from_nick = next_token( &p );
		char* from_id = next_token( &p );
		if ( !from_handle || !from_nick || !from_id )
			return;
		ltrim( &p );
		char* text = p;
		if ( !*text )
			return;

		RelayChat* chat = chat_get_or_create( c, from_handle, from_nick, from_id );
		if ( !chat )
			return;

		chat_move_front( c, chat );
		chat_append_msg( chat, chat->display_name, text );
		if ( c->active != chat )
			chat->unread++;

		set_status_locked( c, "message from %s", chat->display_name );
		if ( c->callbacks.on_message )
			c->callbacks.on_message( c, chat->display_name, text, c->cb_user );
		return;
	}

	if ( starts_with( line, "OUT " ) ) {
		char* tok[3];
		if ( !parse_tokens( line, "OUT ", tok, 3 ) )
			return;
		char* target_handle = tok[0];
		char* target_nick = tok[1];
		char* target_id = tok[2];

		RelayChat* chat = chat_get_or_create( c, target_handle, target_nick, target_id );
		if ( !chat )
			return;

		chat_move_front( c, chat );
		set_status_locked( c, "sent to %s", chat->display_name );
		return;
	}

	if ( starts_with( line, "SYS " ) || starts_with( line, "ERR " ) ) {
		set_status_locked( c, "%s", line + 4 );
		return;
	}

	if ( starts_with( line, "OK AUTH " ) ) {
		char* tok[3];
		if ( !parse_tokens( line, "OK AUTH ", tok, 3 ) )
			return;
		snprintf( c->my_handle, sizeof( c->my_handle ), "%s", tok[0] );
		snprintf( c->my_nick, sizeof( c->my_nick ), "%s", tok[1] );
		snprintf( c->my_id, sizeof( c->my_id ), "%s", tok[2] );
		set_status_locked( c, "connected as %s", c->my_nick );
		return;
	}

	if ( starts_with( line, "USERS" ) ) {
		set_status_locked( c, "online list updated" );
		return;
	}

	if ( strcmp( line, "PONG" ) == 0 ) {
		set_status_locked( c, "pong" );
	}
}

static int wait_for_auth_ack( RelayClient* c, const char* handle, const char* display_name, const char* pubkey_hex, char* err, size_t errcap )
{
	uint8_t buf[MAX_LINE];

	for ( int i = 0; i < 40; i++ ) {
		if ( conn_wait( &c->conn, 100 ) <= 0 )
			continue;

		Client* sender = NULL;
		int		n = conn_recv( &c->conn, buf, sizeof( buf ) - 1, &sender );
		if ( n <= 0 )
			continue;

		buf[n] = '\0';
		trim_eol( (char*) buf );

		if ( starts_with( (char*) buf, "AUTH_CHALLENGE " ) ) {
			char* tok[2];
			if ( !parse_tokens( (char*) buf, "AUTH_CHALLENGE ", tok, 2 ) )
				continue;

			uint64_t nonce = 0;
			uint8_t	 server_pub[32];
			uint8_t	 shared_secret[32];
			uint8_t	 proof[32];
			char	 proof_hex[65];

			if ( !parse_u64_hex( tok[0], &nonce ) )
				continue;
			if ( !hex_decode( tok[1], server_pub, sizeof( server_pub ) ) )
				continue;
			if ( sqnet_x25519_shared_secret( c->id_priv, server_pub, shared_secret ) != 0 )
				continue;
			if ( compute_handshake_proof( shared_secret, nonce, 0, 0, 0x41u, proof ) != 0 ) {
				memset( shared_secret, 0, sizeof( shared_secret ) );
				continue;
			}
			memset( shared_secret, 0, sizeof( shared_secret ) );
			hex_encode( proof, sizeof( proof ), proof_hex, sizeof( proof_hex ) );
			send_linef( c, "AUTH_PROOF %s", proof_hex );
		} else if ( starts_with( (char*) buf, "OK AUTH " ) ) {
			char* tok[3];
			if ( !parse_tokens( (char*) buf, "OK AUTH ", tok, 3 ) )
				continue;
			if ( strcmp( tok[0], handle ) == 0 && strcmp( tok[1], display_name ) == 0 && strcmp( tok[2], pubkey_hex ) == 0 )
				return 1;
		} else if ( starts_with( (char*) buf, "ERR " ) ) {
			snprintf( err, errcap, "%s", (char*) buf + 4 );
			return 0;
		}
	}

	snprintf( err, errcap, "no response from server" );
	return 0;
}

static void* net_thread_main( void* arg )
{
	RelayClient* c = (RelayClient*) arg;

	while ( c->running ) {
		int rc = relay_client_poll( c, 500 );
		if ( rc < 0 )
			break;
	}

	return NULL;
}

int relay_client_create( RelayClient** out, const RelayConfig* cfg )
{
	if ( !out )
		return 0;

	RelayClient* c = (RelayClient*) calloc( 1, sizeof( *c ) );
	if ( !c )
		return 0;

	pthread_mutexattr_t lock_attr;
	pthread_mutexattr_init( &lock_attr );
	pthread_mutexattr_settype( &lock_attr, PTHREAD_MUTEX_RECURSIVE );
	pthread_mutex_init( &c->lock, &lock_attr );
	pthread_mutexattr_destroy( &lock_attr );
	c->running = 0;
	c->connected = 0;

	if ( cfg ) {
		c->callbacks = cfg->callbacks;
		c->cb_user = cfg->user;
		if ( cfg->storage_dir )
			snprintf( c->storage_dir, sizeof( c->storage_dir ), "%s", cfg->storage_dir );
	}

	conn_init();
	*out = c;
	return 1;
}

void relay_client_destroy( RelayClient* c )
{
	if ( !c )
		return;

	relay_client_stop( c );
	conn_close( &c->conn );

	pthread_mutex_lock( &c->lock );
	free_chats( c );
	pthread_mutex_unlock( &c->lock );

	pthread_mutex_destroy( &c->lock );
	free( c );
}

int relay_client_connect( RelayClient* c, const char* host, uint16_t port )
{
	if ( !c || !host )
		return 0;

	c->conn = conn_socket();
	if ( conn_connect( &c->conn, host, port ) != 0 ) {
		pthread_mutex_lock( &c->lock );
		set_status_locked( c, "failed to connect" );
		pthread_mutex_unlock( &c->lock );
		return 0;
	}

	pthread_mutex_lock( &c->lock );
	c->connected = 1;
	set_status_locked( c, "connected" );
	pthread_mutex_unlock( &c->lock );
	return 1;
}

int relay_client_login( RelayClient* c, const char* handle, const char* display_name, char* err, size_t errcap )
{
	if ( !c || !handle || !*handle || !display_name || !*display_name )
		return 0;

	if ( !valid_handle( handle ) || !valid_display_name( display_name ) )
		return 0;

	if ( !c->connected ) {
		pthread_mutex_lock( &c->lock );
		set_status_locked( c, "not connected" );
		pthread_mutex_unlock( &c->lock );
		return 0;
	}

	if ( !load_or_create_identity( c, c->id_pub, c->id_priv ) ) {
		pthread_mutex_lock( &c->lock );
		set_status_locked( c, "failed to load/create identity" );
		pthread_mutex_unlock( &c->lock );
		return 0;
	}

	hex_encode( c->id_pub, 32, c->my_id, sizeof( c->my_id ) );
	send_linef( c, "AUTH %s %s %s", handle, display_name, c->my_id );

	char errbuf[256] = { 0 };
	if ( !wait_for_auth_ack( c, handle, display_name, c->my_id, errbuf, sizeof( errbuf ) ) ) {
		if ( err && errcap )
			snprintf( err, errcap, "%s", errbuf[0] ? errbuf : "unknown" );
		pthread_mutex_lock( &c->lock );
		set_status_locked( c, "auth rejected: %s", errbuf[0] ? errbuf : "unknown" );
		pthread_mutex_unlock( &c->lock );
		return 0;
	}

	pthread_mutex_lock( &c->lock );
	snprintf( c->my_handle, sizeof( c->my_handle ), "%s", handle );
	snprintf( c->my_nick, sizeof( c->my_nick ), "%s", display_name );
	set_status_locked( c, "connected as %s", c->my_nick );
	pthread_mutex_unlock( &c->lock );
	return 1;
}

void relay_client_disconnect( RelayClient* c )
{
	if ( !c )
		return;

	relay_client_stop( c );
	conn_close( &c->conn );

	pthread_mutex_lock( &c->lock );
	c->connected = 0;
	set_status_locked( c, "disconnected" );
	pthread_mutex_unlock( &c->lock );
}

int relay_client_start( RelayClient* c )
{
	if ( !c )
		return 0;
	if ( c->net_thread_started )
		return 1;

	c->running = 1;
	if ( pthread_create( &c->net_thread, NULL, net_thread_main, c ) != 0 ) {
		c->running = 0;
		return 0;
	}

	c->net_thread_started = 1;
	return 1;
}

void relay_client_stop( RelayClient* c )
{
	if ( !c || !c->net_thread_started )
		return;

	c->running = 0;
	pthread_join( c->net_thread, NULL );
	c->net_thread_started = 0;
}

int relay_client_poll( RelayClient* c, int timeout_ms )
{
	if ( !c || !c->connected )
		return -1;

	if ( conn_wait( &c->conn, timeout_ms ) <= 0 )
		return 0;

	uint8_t buf[MAX_LINE];
	Client* sender = NULL;
	int		n = conn_recv( &c->conn, buf, sizeof( buf ) - 1, &sender );
	if ( n < 0 ) {
		pthread_mutex_lock( &c->lock );
		set_status_locked( c, "disconnected" );
		c->connected = 0;
		c->running = 0;
		if ( c->callbacks.on_disconnect )
			c->callbacks.on_disconnect( c, c->cb_user );
		pthread_mutex_unlock( &c->lock );
		return -1;
	}

	if ( n == 0 )
		return 0;

	buf[n] = '\0';
	trim_eol( (char*) buf );

	pthread_mutex_lock( &c->lock );
	handle_server_line( c, (char*) buf );
	pthread_mutex_unlock( &c->lock );
	return 1;
}

int relay_client_open_chat( RelayClient* c, const char* handle )
{
	if ( !c || !handle || !*handle || !valid_handle( handle ) )
		return 0;

	pthread_mutex_lock( &c->lock );
	RelayChat* chat = chat_get_or_create( c, handle, NULL, NULL );
	if ( chat ) {
		chat_move_front( c, chat );
		c->active = chat;
		chat->unread = 0;
		set_status_locked( c, "opened chat with %s", chat->display_name );
	}
	pthread_mutex_unlock( &c->lock );
	return chat != NULL;
}

int relay_client_next_chat( RelayClient* c )
{
	if ( !c )
		return 0;

	pthread_mutex_lock( &c->lock );
	if ( c->chats ) {
		if ( !c->active )
			c->active = c->chats;
		else if ( c->active->next )
			c->active = c->active->next;
		else
			c->active = c->chats;

		if ( c->active )
			c->active->unread = 0;

		set_status_locked( c, "opened chat with %s", c->active->display_name );
		pthread_mutex_unlock( &c->lock );
		return 1;
	}

	set_status_locked( c, "no chats yet" );
	pthread_mutex_unlock( &c->lock );
	return 0;
}

int relay_client_set_active_chat( RelayClient* c, const char* handle )
{
	if ( !c || !handle || !*handle || !valid_handle( handle ) )
		return 0;

	pthread_mutex_lock( &c->lock );
	RelayChat* chat = chat_find( c, handle, NULL );
	if ( chat ) {
		c->active = chat;
		chat->unread = 0;
		set_status_locked( c, "opened chat with %s", chat->display_name );
		pthread_mutex_unlock( &c->lock );
		return 1;
	}

	pthread_mutex_unlock( &c->lock );
	return 0;
}

int relay_client_send_active( RelayClient* c, const char* text )
{
	if ( !c || !text )
		return 0;

	pthread_mutex_lock( &c->lock );
	if ( !c->active ) {
		set_status_locked( c, "open a contact first" );
		pthread_mutex_unlock( &c->lock );
		return 0;
	}

	RelayChat* chat = c->active;
	char	   target[MAX_NICK + 1];
	snprintf( target, sizeof( target ), "%s", chat->handle );

	chat_append_msg( chat, "me", text );

	if ( chat->e2e.established ) {
		if ( !e2e_send_encrypted_locked( c, chat, text ) )
			set_status_locked( c, "failed to send encrypted message to %s", chat->display_name );
		else
			set_status_locked( c, "sent to %s", chat->display_name );
	} else {
		e2e_queue_pending_locked( chat, text );
		if ( !chat->e2e.sent_hello )
			e2e_start_handshake_locked( c, chat );
		else
			set_status_locked( c, "waiting for E2E with %s", chat->display_name );
	}

	pthread_mutex_unlock( &c->lock );
	return 1;
}

int relay_client_send( RelayClient* c, const char* handle, const char* text )
{
	if ( !c || !handle || !*handle || !text || !valid_handle( handle ) )
		return 0;

	pthread_mutex_lock( &c->lock );
	RelayChat* chat = chat_get_or_create( c, handle, NULL, NULL );
	if ( !chat ) {
		pthread_mutex_unlock( &c->lock );
		return 0;
	}

	chat_append_msg( chat, "me", text );
	chat_move_front( c, chat );

	if ( chat->e2e.established ) {
		if ( !e2e_send_encrypted_locked( c, chat, text ) )
			set_status_locked( c, "failed to send encrypted message to %s", chat->display_name );
		else
			set_status_locked( c, "sent to %s", chat->display_name );
	} else {
		e2e_queue_pending_locked( chat, text );
		if ( !chat->e2e.sent_hello )
			e2e_start_handshake_locked( c, chat );
		else
			set_status_locked( c, "waiting for E2E with %s", chat->display_name );
	}

	pthread_mutex_unlock( &c->lock );
	return 1;
}

void relay_client_lock( RelayClient* c )
{
	if ( c )
		pthread_mutex_lock( &c->lock );
}

void relay_client_unlock( RelayClient* c )
{
	if ( c )
		pthread_mutex_unlock( &c->lock );
}

const RelayChat* relay_client_chats( RelayClient* c )
{
	return c ? c->chats : NULL;
}

const RelayChat* relay_client_active_chat( RelayClient* c )
{
	return c ? c->active : NULL;
}

const char* relay_client_status( RelayClient* c )
{
	return c ? c->status : "";
}

const char* relay_client_nick( RelayClient* c )
{
	return c ? c->my_nick : "";
}

const char* relay_client_handle( RelayClient* c )
{
	return c ? c->my_handle : "";
}

const char* relay_client_id( RelayClient* c )
{
	return c ? c->my_id : "";
}

int relay_client_is_connected( RelayClient* c )
{
	return c ? c->connected : 0;
}

int relay_client_is_running( RelayClient* c )
{
	return c ? c->running : 0;
}

const RelayChat* relay_chat_next( const RelayChat* chat )
{
	return chat ? chat->next : NULL;
}

const char* relay_chat_nick( const RelayChat* chat )
{
	return chat ? chat->display_name : "";
}

const char* relay_chat_handle( const RelayChat* chat )
{
	return chat ? chat->handle : "";
}

const char* relay_chat_id( const RelayChat* chat )
{
	return chat ? chat->id : "";
}

const char* relay_chat_display_name( const RelayChat* chat )
{
	return chat ? chat->display_name : "";
}

int relay_chat_unread( const RelayChat* chat )
{
	return chat ? chat->unread : 0;
}

int relay_chat_msg_count( const RelayChat* chat )
{
	return chat ? chat->msg_count : 0;
}

int relay_chat_e2e_established( const RelayChat* chat )
{
	return chat ? chat->e2e.established : 0;
}

const RelayMsg* relay_chat_messages( const RelayChat* chat )
{
	return chat ? chat->head : NULL;
}

const RelayMsg* relay_msg_next( const RelayMsg* msg )
{
	return msg ? msg->next : NULL;
}

const char* relay_msg_from( const RelayMsg* msg )
{
	return msg ? msg->from : "";
}

const char* relay_msg_text( const RelayMsg* msg )
{
	return msg ? msg->text : "";
}
