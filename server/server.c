#include "relay_common.h"
#include "sqNet/sqNet.h"
#include "sqNet/sqNet_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>

#define HANDLE_DB_PATH ".relay_handles.txt"
#define AUTH_CHALLENGE_TTL 30
#define AUTH_ROLE_TAG 0x41u

typedef struct Peer
{
	Client*		 client;
	char		 handle[MAX_NICK + 1];
	char		 display[MAX_DISPLAY + 1];
	char		 pubkey[65];
	int			 has_auth;
	int			 auth_pending;
	time_t		 auth_issued_at;
	char		 pending_handle[MAX_NICK + 1];
	char		 pending_display[MAX_DISPLAY + 1];
	char		 pending_pubkey[65];
	uint64_t	 auth_nonce;
	uint8_t		 auth_server_pub[32];
	uint8_t		 auth_server_priv[32];
	struct Peer* next;
} Peer;

static Conn			server;
static Peer*		peers = NULL;
static volatile int running = 1;

static void trim_eol( char* s )
{
	size_t n = strlen( s );
	while ( n > 0 && ( s[n - 1] == '\n' || s[n - 1] == '\r' ) ) {
		s[--n] = '\0';
	}
}

static void ltrim( char** s )
{
	while ( **s == ' ' || **s == '\t' )
		( *s )++;
}

static void rtrim( char* s )
{
	size_t n = strlen( s );
	while ( n > 0 && ( s[n - 1] == ' ' || s[n - 1] == '\t' ) ) {
		s[--n] = '\0';
	}
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

static int valid_name_token( const char* nick, size_t max_len )
{
	size_t len = strlen( nick );
	if ( len < 3 || len > max_len )
		return 0;

	for ( size_t i = 0; i < len; i++ ) {
		unsigned char c = (unsigned char) nick[i];
		if ( !( isalnum( c ) || c == '_' || c == '-' ) )
			return 0;
	}

	return 1;
}

static int valid_handle( const char* handle )
{
	return valid_name_token( handle, MAX_NICK );
}

static int valid_display( const char* display )
{
	return valid_name_token( display, MAX_DISPLAY );
}

static int valid_pubkey_hex( const char* pubkey )
{
	if ( !pubkey || strlen( pubkey ) != 64 )
		return 0;

	for ( size_t i = 0; i < 64; i++ ) {
		if ( !isxdigit( (unsigned char) pubkey[i] ) )
			return 0;
	}

	return 1;
}

static void hex_encode( const uint8_t* in, size_t len, char* out, size_t outcap )
{
	static const char hex[] = "0123456789abcdef";

	if ( !out || outcap < len * 2 + 1 ) {
		if ( out && outcap )
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
	size_t len = in ? strlen( in ) : 0;
	if ( ( len & 1u ) != 0 || len / 2 > outcap )
		return 0;

	for ( size_t i = 0; i < len / 2; i++ ) {
		int hi = hex_nibble( in[i * 2] );
		int lo = hex_nibble( in[i * 2 + 1] );
		if ( hi < 0 || lo < 0 )
			return 0;
		out[i] = (uint8_t) ( ( hi << 4 ) | lo );
	}

	return 1;
}

static void clear_pending_auth( Peer* p )
{
	if ( !p )
		return;

	p->auth_pending = 0;
	p->auth_issued_at = 0;
	p->pending_handle[0] = '\0';
	p->pending_display[0] = '\0';
	p->pending_pubkey[0] = '\0';
	p->auth_nonce = 0;
	memset( p->auth_server_pub, 0, sizeof( p->auth_server_pub ) );
	memset( p->auth_server_priv, 0, sizeof( p->auth_server_priv ) );
}

static int client_alive( Client* c )
{
	for ( Client* it = conn_clients( &server ); it; it = it->next ) {
		if ( it == c )
			return 1;
	}
	return 0;
}

static Peer* peer_find_by_client( Client* c )
{
	for ( Peer* p = peers; p; p = p->next ) {
		if ( p->client == c )
			return p;
	}
	return NULL;
}

static Peer* peer_find_by_pubkey( const char* pubkey )
{
	for ( Peer* p = peers; p; p = p->next ) {
		if ( p->has_auth && strcmp( p->pubkey, pubkey ) == 0 )
			return p;
	}
	return NULL;
}

static Peer* peer_find_by_handle( const char* handle )
{
	for ( Peer* p = peers; p; p = p->next ) {
		if ( p->has_auth && strcmp( p->handle, handle ) == 0 )
			return p;
	}
	return NULL;
}

static int registry_lookup_handle( const char* handle, char pubkey[65] )
{
	FILE* f = fopen( HANDLE_DB_PATH, "r" );
	if ( !f )
		return 0;

	char file_handle[MAX_NICK + 1];
	char file_pubkey[65];
	int	 found = 0;

	while ( fscanf( f, "%31s %64s", file_handle, file_pubkey ) == 2 ) {
		if ( strcmp( file_handle, handle ) == 0 ) {
			snprintf( pubkey, 65, "%s", file_pubkey );
			found = 1;
			break;
		}
	}

	fclose( f );
	return found;
}

static int registry_lookup_pubkey( const char* pubkey, char handle[MAX_NICK + 1] )
{
	FILE* f = fopen( HANDLE_DB_PATH, "r" );
	if ( !f )
		return 0;

	char file_handle[MAX_NICK + 1];
	char file_pubkey[65];
	int	 found = 0;

	while ( fscanf( f, "%31s %64s", file_handle, file_pubkey ) == 2 ) {
		if ( strcmp( file_pubkey, pubkey ) == 0 ) {
			snprintf( handle, MAX_NICK + 1, "%s", file_handle );
			found = 1;
			break;
		}
	}

	fclose( f );
	return found;
}

static int registry_bind_handle( const char* handle, const char* pubkey )
{
	char bound_pubkey[65];
	if ( registry_lookup_handle( handle, bound_pubkey ) )
		return strcmp( bound_pubkey, pubkey ) == 0;

	FILE* f = fopen( HANDLE_DB_PATH, "a" );
	if ( !f )
		return 0;

	fprintf( f, "%s %s\n", handle, pubkey );
	fclose( f );
	return 1;
}

static Peer* peer_get_or_create( Client* c )
{
	Peer* p = peer_find_by_client( c );
	if ( p )
		return p;

	p = (Peer*) calloc( 1, sizeof( Peer ) );
	if ( !p )
		return NULL;

	p->client = c;
	snprintf( p->handle, sizeof( p->handle ), "guest%u", (unsigned) ntohs( c->addr.sin_port ) );
	snprintf( p->display, sizeof( p->display ), "%s", p->handle );
	p->pubkey[0] = '\0';
	p->has_auth = 0;
	p->next = peers;
	peers = p;

	return p;
}

static void sendf( Client* c, const char* fmt, ... )
{
	char buf[MAX_LINE];

	va_list ap;
	va_start( ap, fmt );
	vsnprintf( buf, sizeof( buf ), fmt, ap );
	va_end( ap );

	size_t len = strlen( buf );
	if ( len == 0 )
		return;

	if ( len + 1 < sizeof( buf ) && buf[len - 1] != '\n' ) {
		buf[len++] = '\n';
		buf[len] = '\0';
	}

	conn_send( &server, (uint8_t*) buf, len, c );
}

static void broadcast_sys( Client* except, const char* fmt, ... )
{
	char buf[MAX_LINE];

	va_list ap;
	va_start( ap, fmt );
	vsnprintf( buf, sizeof( buf ), fmt, ap );
	va_end( ap );

	size_t len = strlen( buf );
	if ( len == 0 )
		return;

	if ( len + 1 < sizeof( buf ) && buf[len - 1] != '\n' ) {
		buf[len++] = '\n';
		buf[len] = '\0';
	}

	for ( Client* c = conn_clients( &server ); c; ) {
		Client* next = c->next;
		if ( c == except ) {
			c = next;
			continue;
		}
		conn_send( &server, (uint8_t*) buf, len, c );
		c = next;
	}
}

static void prune_disconnected( void )
{
	Peer** pp = &peers;
	while ( *pp ) {
		Peer* p = *pp;
		if ( !client_alive( p->client ) ) {
			char display[MAX_DISPLAY + 1];
			snprintf( display, sizeof( display ), "%s", p->display );
			int had_auth = p->has_auth;

			*pp = p->next;
			free( p );

			if ( had_auth )
				broadcast_sys( NULL, "SYS %s left", display );
			continue;
		}
		pp = &p->next;
	}
}

static void handle_auth( Peer* p, char* args )
{
	ltrim( &args );

	char* handle = next_token( &args );
	char* display = next_token( &args );
	char* pubkey = next_token( &args );
	if ( !handle || !display || !pubkey ) {
		sendf( p->client, "ERR usage: AUTH <handle> <display> <pubkey>" );
		return;
	}

	rtrim( handle );
	rtrim( display );
	rtrim( pubkey );

	if ( !valid_handle( handle ) ) {
		sendf( p->client, "ERR invalid handle" );
		return;
	}

	if ( !valid_display( display ) ) {
		sendf( p->client, "ERR invalid display" );
		return;
	}

	if ( !valid_pubkey_hex( pubkey ) ) {
		sendf( p->client, "ERR invalid pubkey" );
		return;
	}

	if ( sqrand_bytes( (unsigned char*) &p->auth_nonce, sizeof( p->auth_nonce ) ) != 1 || p->auth_nonce == 0 ) {
		sendf( p->client, "ERR failed to create auth challenge" );
		clear_pending_auth( p );
		return;
	}

	if ( sqnet_generate_x25519_keypair( p->auth_server_pub, p->auth_server_priv ) != 0 ) {
		sendf( p->client, "ERR failed to create auth challenge" );
		clear_pending_auth( p );
		return;
	}

	snprintf( p->pending_handle, sizeof( p->pending_handle ), "%s", handle );
	snprintf( p->pending_display, sizeof( p->pending_display ), "%s", display );
	snprintf( p->pending_pubkey, sizeof( p->pending_pubkey ), "%s", pubkey );
	p->auth_pending = 1;
	p->auth_issued_at = time( NULL );

	char nonce_hex[17];
	char server_pub_hex[65];
	snprintf( nonce_hex, sizeof( nonce_hex ), "%016llx", (unsigned long long) p->auth_nonce );
	hex_encode( p->auth_server_pub, sizeof( p->auth_server_pub ), server_pub_hex, sizeof( server_pub_hex ) );
	sendf( p->client, "AUTH_CHALLENGE %s %s", nonce_hex, server_pub_hex );
}

static void handle_auth_proof( Peer* p, char* args )
{
	ltrim( &args );
	rtrim( args );

	if ( !p->auth_pending ) {
		sendf( p->client, "ERR no auth challenge pending" );
		return;
	}

	time_t now = time( NULL );
	if ( now == (time_t) -1 || now - p->auth_issued_at > AUTH_CHALLENGE_TTL ) {
		clear_pending_auth( p );
		sendf( p->client, "ERR auth challenge expired" );
		return;
	}

	uint8_t proof[32];
	if ( !hex_decode( args, proof, sizeof( proof ) ) || strlen( args ) != 64 ) {
		clear_pending_auth( p );
		sendf( p->client, "ERR invalid auth proof" );
		return;
	}

	uint8_t client_pub[32];
	uint8_t shared_secret[32];
	uint8_t expected[32];
	if ( !hex_decode( p->pending_pubkey, client_pub, sizeof( client_pub ) ) ) {
		clear_pending_auth( p );
		sendf( p->client, "ERR invalid pending pubkey" );
		return;
	}

	if ( sqnet_x25519_shared_secret( p->auth_server_priv, client_pub, shared_secret ) != 0
		|| compute_handshake_proof( shared_secret, p->auth_nonce, 0, 0, AUTH_ROLE_TAG, expected ) != 0 ) {
		memset( shared_secret, 0, sizeof( shared_secret ) );
		clear_pending_auth( p );
		sendf( p->client, "ERR failed to verify auth proof" );
		return;
	}

	memset( shared_secret, 0, sizeof( shared_secret ) );

	if ( memcmp( expected, proof, sizeof( proof ) ) != 0 ) {
		clear_pending_auth( p );
		sendf( p->client, "ERR auth proof mismatch" );
		return;
	}

	char bound_handle[MAX_NICK + 1];
	if ( registry_lookup_pubkey( p->pending_pubkey, bound_handle ) && strcmp( bound_handle, p->pending_handle ) != 0 ) {
		clear_pending_auth( p );
		sendf( p->client, "ERR identity already bound to another handle" );
		return;
	}

	char bound_pubkey[65];
	if ( registry_lookup_handle( p->pending_handle, bound_pubkey ) && strcmp( bound_pubkey, p->pending_pubkey ) != 0 ) {
		clear_pending_auth( p );
		sendf( p->client, "ERR handle owned by another identity" );
		return;
	}

	Peer* taken = peer_find_by_pubkey( p->pending_pubkey );
	if ( taken && taken != p ) {
		clear_pending_auth( p );
		sendf( p->client, "ERR key already connected" );
		return;
	}

	Peer* handle_taken = peer_find_by_handle( p->pending_handle );
	if ( handle_taken && handle_taken != p ) {
		clear_pending_auth( p );
		sendf( p->client, "ERR handle already online" );
		return;
	}

	if ( !registry_bind_handle( p->pending_handle, p->pending_pubkey ) ) {
		clear_pending_auth( p );
		sendf( p->client, "ERR failed to bind handle" );
		return;
	}

	char old_display[MAX_DISPLAY + 1];
	snprintf( old_display, sizeof( old_display ), "%s", p->display );

	int was_auth = p->has_auth;
	snprintf( p->handle, sizeof( p->handle ), "%s", p->pending_handle );
	snprintf( p->display, sizeof( p->display ), "%s", p->pending_display );
	snprintf( p->pubkey, sizeof( p->pubkey ), "%s", p->pending_pubkey );
	p->has_auth = 1;
	clear_pending_auth( p );

	sendf( p->client, "OK AUTH %s %s %s", p->handle, p->display, p->pubkey );

	if ( !was_auth ) {
		broadcast_sys( p->client, "SYS %s joined", p->display );
	} else if ( strcmp( old_display, p->display ) != 0 ) {
		broadcast_sys( p->client, "SYS %s is now %s", old_display, p->display );
	}
}

static void handle_dm( Peer* sender, char* rest )
{
	ltrim( &rest );

	char* sp = strchr( rest, ' ' );
	if ( !sp ) {
		sendf( sender->client, "ERR usage: DM <handle> <text>" );
		return;
	}

	*sp = '\0';
	char* target_handle = rest;
	char* text = sp + 1;

	ltrim( &text );
	rtrim( text );

	if ( !sender->has_auth ) {
		sendf( sender->client, "ERR not authenticated" );
		return;
	}

	if ( !*target_handle || !*text ) {
		sendf( sender->client, "ERR usage: DM <handle> <text>" );
		return;
	}

	Peer* target = peer_find_by_handle( target_handle );
	if ( !target || !client_alive( target->client ) ) {
		sendf( sender->client, "ERR user not found" );
		return;
	}

	sendf( target->client, "IN %s %s %s %s", sender->handle, sender->display, sender->pubkey, text );
	sendf( sender->client, "OUT %s %s %s", target->handle, target->display, target->pubkey );
}

static void route_e2e( Peer* sender, char* line )
{
	char tmp[MAX_LINE];
	snprintf( tmp, sizeof( tmp ), "%s", line );

	char* p = tmp;
	char* cmd = next_token( &p );
	char* target = next_token( &p );
	if ( !cmd || !target ) {
		sendf( sender->client, "ERR bad E2E packet" );
		return;
	}

	if ( !sender->has_auth ) {
		sendf( sender->client, "ERR not authenticated" );
		return;
	}

	Peer* dest = peer_find_by_handle( target );
	if ( !dest || !client_alive( dest->client ) ) {
		sendf( sender->client, "ERR user not found" );
		return;
	}

	ltrim( &p );

	char out[MAX_LINE];
	if ( *p )
		snprintf( out, sizeof( out ), "%s %s %s %s %s %s", cmd, sender->handle, sender->display, sender->pubkey, target, p );
	else
		snprintf( out, sizeof( out ), "%s %s %s %s %s", cmd, sender->handle, sender->display, sender->pubkey, target );

	sendf( dest->client, "%s", out );
}

static void handle_who( Peer* p )
{
	char   out[MAX_LINE];
	size_t pos = 0;

	pos += snprintf( out + pos, sizeof( out ) - pos, "USERS" );

	for ( Peer* it = peers; it; it = it->next ) {
		if ( !client_alive( it->client ) || !it->has_auth )
			continue;

		if ( pos + 2 >= sizeof( out ) )
			break;

		pos += snprintf( out + pos, sizeof( out ) - pos, " %s:%s:%s", it->handle, it->display, it->pubkey );
	}

	sendf( p->client, "%s", out );
}

static void handle_line( Client* sender_client, char* line )
{
	trim_eol( line );

	char* p = line;
	ltrim( &p );
	rtrim( p );

	if ( *p == '\0' )
		return;

	Peer* sender = peer_get_or_create( sender_client );
	if ( !sender )
		return;

	if ( strncmp( p, "AUTH ", 5 ) == 0 ) {
		handle_auth( sender, p + 5 );
		return;
	}

	if ( strncmp( p, "AUTH_PROOF ", 11 ) == 0 ) {
		handle_auth_proof( sender, p + 11 );
		return;
	}

	if ( strncmp( p, "DM ", 3 ) == 0 ) {
		handle_dm( sender, p + 3 );
		return;
	}

	if ( strncmp( p, "E2E_", 4 ) == 0 ) {
		route_e2e( sender, p );
		return;
	}

	if ( strncmp( p, "WHO", 3 ) == 0 && ( p[3] == '\0' || isspace( (unsigned char) p[3] ) ) ) {
		handle_who( sender );
		return;
	}

	if ( strncmp( p, "PING", 4 ) == 0 ) {
		sendf( sender->client, "PONG" );
		return;
	}

	sendf( sender->client, "ERR unknown command" );
}

int main( void )
{
	conn_init();
	server = conn_socket();

	uint16_t port = 7777;
	if ( conn_bind( &server, "0.0.0.0", port ) != 0 ) {
		fprintf( stderr, "bind failed\n" );
		return 1;
	}

	printf( "Server listening on port %d\n", port );

	uint8_t buf[MAX_LINE];

	while ( running ) {
		prune_disconnected();

		int ready = conn_wait( &server, 1000 );
		if ( ready <= 0 )
			continue;

		Client* sender = NULL;
		int		n = conn_recv( &server, buf, sizeof( buf ) - 1, &sender );
		if ( n <= 0 || !sender )
			continue;

		buf[n] = '\0';
		handle_line( sender, (char*) buf );
	}

	conn_close( &server );
	return 0;
}
