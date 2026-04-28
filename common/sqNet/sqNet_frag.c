#include "sqNet_internal.h"

#define CONN_FRAGMENT_DATA_SIZE 1024u
#define CONN_MAX_MESSAGE_SIZE ( 4u * 1024u * 1024u )
#define CONN_MAX_FRAGMENTS ( ( CONN_MAX_MESSAGE_SIZE + CONN_FRAGMENT_DATA_SIZE - 1u ) / CONN_FRAGMENT_DATA_SIZE )
#define CONN_FRAGMENT_TIMEOUT 10
#define CONN_MAX_ACTIVE_ASSEMBLIES 128u
#define CONN_MAX_ACTIVE_ASSEMBLIES_PER_SOCKET 32u
#define CONN_MAX_ACTIVE_ASSEMBLY_BYTES ( 8u * 1024u * 1024u )

enum
{
	FRAG_OFF_MSG_ID = 0u,
	FRAG_OFF_INDEX = FRAG_OFF_MSG_ID + (uint32_t) sizeof( uint32_t ),
	FRAG_OFF_COUNT = FRAG_OFF_INDEX + (uint32_t) sizeof( uint16_t ),
	FRAG_OFF_HASH = FRAG_OFF_COUNT + (uint32_t) sizeof( uint16_t ),
	FRAG_HEADER_SIZE = FRAG_OFF_HASH + (uint32_t) sizeof( uint32_t )
};

typedef struct FragmentAssembly
{
	int						 sockfd;
	struct sockaddr_in		 addr;
	uint32_t				 msg_id;
	uint16_t				 frag_count;
	time_t					 last_seen;
	uint8_t*				 data;
	uint8_t*				 received;
	uint16_t				 last_frag_len;
	struct FragmentAssembly* next;
} FragmentAssembly;

static FragmentAssembly* g_assemblies = NULL;
static size_t			 g_assembly_count = 0;
static size_t			 g_assembly_bytes = 0;

static void free_assembly( FragmentAssembly* a )
{
	if ( !a )
		return;

	if ( g_assembly_count > 0 )
		g_assembly_count--;
	g_assembly_bytes -= (size_t) a->frag_count * CONN_FRAGMENT_DATA_SIZE;
	free( a->data );
	free( a->received );
	free( a );
}

static size_t count_socket_assemblies( int sockfd )
{
	size_t count = 0;
	for ( FragmentAssembly* cur = g_assemblies; cur; cur = cur->next ) {
		if ( cur->sockfd == sockfd )
			count++;
	}
	return count;
}

static int deliver_payload( const uint8_t* src, size_t len, void* dst, size_t dst_size, Client* c, Client** sender )
{
	if ( len > dst_size ) {
		LOGE( "Receive buffer too small: payload=%zu buffer=%zu", len, dst_size );
		return -1;
	}

	if ( dst && src && len )
		memcpy( dst, src, len );

	if ( sender )
		*sender = c;

	return (int) len;
}

static FragmentAssembly* find_assembly( int sockfd, const struct sockaddr_in* addr, uint32_t msg_id )
{
	for ( FragmentAssembly* cur = g_assemblies; cur; cur = cur->next ) {
		if ( cur->sockfd == sockfd && cur->msg_id == msg_id && same_addr( &cur->addr, addr ) )
			return cur;
	}
	return NULL;
}

static FragmentAssembly* create_assembly( int sockfd, const struct sockaddr_in* addr, uint32_t msg_id, uint16_t frag_count )
{
	size_t assembly_bytes;

	if ( frag_count == 0 || frag_count > CONN_MAX_FRAGMENTS )
		return NULL;
	if ( g_assembly_count >= CONN_MAX_ACTIVE_ASSEMBLIES )
		return NULL;
	if ( count_socket_assemblies( sockfd ) >= CONN_MAX_ACTIVE_ASSEMBLIES_PER_SOCKET )
		return NULL;

	assembly_bytes = (size_t) frag_count * CONN_FRAGMENT_DATA_SIZE;
	if ( assembly_bytes > CONN_MAX_ACTIVE_ASSEMBLY_BYTES || g_assembly_bytes > CONN_MAX_ACTIVE_ASSEMBLY_BYTES - assembly_bytes )
		return NULL;

	FragmentAssembly* a = calloc( 1, sizeof( *a ) );
	if ( !a )
		return NULL;

	a->sockfd = sockfd;
	a->addr = *addr;
	a->msg_id = msg_id;
	a->frag_count = frag_count;
	a->last_seen = sqnet_now_sec();

	a->data = malloc( (size_t) frag_count * CONN_FRAGMENT_DATA_SIZE );
	a->received = calloc( frag_count, sizeof( uint8_t ) );

	if ( !a->data || !a->received ) {
		free_assembly( a );
		return NULL;
	}

	a->next = g_assemblies;
	g_assemblies = a;
	g_assembly_count++;
	g_assembly_bytes += assembly_bytes;
	return a;
}

static void remove_assembly( FragmentAssembly* target )
{
	FragmentAssembly** pp = &g_assemblies;

	while ( *pp ) {
		if ( *pp == target ) {
			*pp = target->next;
			free_assembly( target );
			return;
		}
		pp = &( *pp )->next;
	}
}

void cleanup_stale_assemblies( int sockfd, time_t now )
{
	FragmentAssembly** pp = &g_assemblies;

	while ( *pp ) {
		FragmentAssembly* cur = *pp;
		const int		  expired = ( now - cur->last_seen ) > CONN_FRAGMENT_TIMEOUT;

		if ( expired && ( sockfd < 0 || cur->sockfd == sockfd ) ) {
			*pp = cur->next;
			free_assembly( cur );
		} else {
			pp = &cur->next;
		}
	}
}

void cleanup_socket_assemblies( int sockfd )
{
	FragmentAssembly** pp = &g_assemblies;

	while ( *pp ) {
		FragmentAssembly* cur = *pp;

		if ( cur->sockfd == sockfd ) {
			*pp = cur->next;
			free_assembly( cur );
		} else {
			pp = &cur->next;
		}
	}
}

static uint32_t compute_fragment_hash(
	const uint8_t* payload, uint16_t payload_len, uint32_t msg_id, uint16_t frag_index, uint16_t frag_count, uint32_t secret )
{
	uint8_t	 meta[6];
	uint32_t hash = secret ^ msg_id;

	meta[0] = (uint8_t) ( frag_index >> 8 );
	meta[1] = (uint8_t) frag_index;
	meta[2] = (uint8_t) ( frag_count >> 8 );
	meta[3] = (uint8_t) frag_count;
	meta[4] = (uint8_t) ( payload_len >> 8 );
	meta[5] = (uint8_t) payload_len;

	hash = compute_hash( meta, sizeof( meta ), hash );
	hash = compute_hash( payload, payload_len, hash );
	return hash;
}

int send_fragmented_with_keys( Conn* conn, const void* data, size_t len, const uint32_t key[32], uint32_t secret_key, const struct sockaddr_in* addr )
{
	const uint8_t* src = (const uint8_t*) data;
	uint8_t		   fragment[FRAG_HEADER_SIZE + CONN_FRAGMENT_DATA_SIZE];
	uint32_t	   msg_id;
	uint16_t	   frag_count;
	size_t		   offset = 0;

	if ( !conn || !data || len == 0 || !addr )
		return -1;

	if ( len > CONN_MAX_MESSAGE_SIZE ) {
		LOGE( "Payload too large: %zu bytes (max %u)", len, CONN_MAX_MESSAGE_SIZE );
		return -1;
	}

	frag_count = (uint16_t) ( ( len + CONN_FRAGMENT_DATA_SIZE - 1u ) / CONN_FRAGMENT_DATA_SIZE );
	if ( frag_count == 0 || frag_count > CONN_MAX_FRAGMENTS )
		return -1;

	msg_id = (uint32_t) sqrand();
	if ( msg_id == 0 )
		msg_id = 1;

	for ( uint16_t frag_index = 0; frag_index < frag_count; ++frag_index ) {
		const size_t chunk_len = ( len - offset > CONN_FRAGMENT_DATA_SIZE ) ? CONN_FRAGMENT_DATA_SIZE : ( len - offset );

		const uint32_t msg_id_be = htonl( msg_id );
		const uint16_t index_be = htons( frag_index );
		const uint16_t count_be = htons( frag_count );

		memcpy( fragment + FRAG_OFF_MSG_ID, &msg_id_be, sizeof( msg_id_be ) );
		memcpy( fragment + FRAG_OFF_INDEX, &index_be, sizeof( index_be ) );
		memcpy( fragment + FRAG_OFF_COUNT, &count_be, sizeof( count_be ) );
		memcpy( fragment + FRAG_HEADER_SIZE, src + offset, chunk_len );

		const uint32_t hash = compute_fragment_hash( fragment + FRAG_HEADER_SIZE, (uint16_t) chunk_len, msg_id, frag_index, frag_count, secret_key );

		const uint32_t hash_be = htonl( hash );
		memcpy( fragment + FRAG_OFF_HASH, &hash_be, sizeof( hash_be ) );

		if ( send_encrypted_payload( conn, key, secret_key, fragment, FRAG_HEADER_SIZE + chunk_len, addr ) < 0 )
			return -1;

		offset += chunk_len;
	}

	return (int) len;
}

int process_fragmented_payload( Conn* conn, Client* c, const struct sockaddr_in* addr, uint8_t* payload_ptr, size_t payload_len, uint32_t rx_secret,
	void* buf, size_t size, Client** sender )
{
	if ( payload_len < FRAG_HEADER_SIZE )
		return deliver_payload( payload_ptr, payload_len, buf, size, c, sender );

	uint32_t msg_id_net = 0;
	uint16_t frag_index_net = 0;
	uint16_t frag_count_net = 0;
	uint32_t frag_hash_net = 0;

	memcpy( &msg_id_net, payload_ptr + FRAG_OFF_MSG_ID, sizeof( msg_id_net ) );
	memcpy( &frag_index_net, payload_ptr + FRAG_OFF_INDEX, sizeof( frag_index_net ) );
	memcpy( &frag_count_net, payload_ptr + FRAG_OFF_COUNT, sizeof( frag_count_net ) );
	memcpy( &frag_hash_net, payload_ptr + FRAG_OFF_HASH, sizeof( frag_hash_net ) );

	const uint32_t msg_id = ntohl( msg_id_net );
	const uint16_t frag_index = ntohs( frag_index_net );
	const uint16_t frag_count = ntohs( frag_count_net );
	const uint32_t frag_hash = ntohl( frag_hash_net );

	const uint8_t* frag_data = payload_ptr + FRAG_HEADER_SIZE;
	const uint16_t frag_len = (uint16_t) ( payload_len - FRAG_HEADER_SIZE );

	if ( frag_count == 0 || frag_count > CONN_MAX_FRAGMENTS || frag_index >= frag_count ) {
		LOGE( "Invalid fragment header: msg=%u idx=%u count=%u", msg_id, frag_index, frag_count );
		return -1;
	}

	if ( frag_len == 0 || frag_len > CONN_FRAGMENT_DATA_SIZE ) {
		LOGE( "Invalid fragment length: msg=%u idx=%u frag_len=%u payload=%zu", msg_id, frag_index, frag_len, payload_len );
		return -1;
	}

	const uint32_t computed_frag_hash = compute_fragment_hash( frag_data, frag_len, msg_id, frag_index, frag_count, rx_secret );

	if ( frag_hash != computed_frag_hash )
		return deliver_payload( payload_ptr, payload_len, buf, size, c, sender );

	if ( frag_count == 1 )
		return deliver_payload( frag_data, frag_len, buf, size, c, sender );

	FragmentAssembly* a = find_assembly( conn->sockfd, addr, msg_id );
	if ( !a || a->frag_count != frag_count ) {
		if ( a )
			remove_assembly( a );

		a = create_assembly( conn->sockfd, addr, msg_id, frag_count );
		if ( !a ) {
			LOGE( "Unable to allocate fragment assembly: msg=%u count=%u", msg_id, frag_count );
			return -1;
		}
	}

	a->last_seen = sqnet_now_sec();

	if ( !a->received[frag_index] ) {
		memcpy( a->data + (size_t) frag_index * CONN_FRAGMENT_DATA_SIZE, frag_data, frag_len );
		a->received[frag_index] = 1;

		if ( frag_index == (uint16_t) ( frag_count - 1u ) )
			a->last_frag_len = frag_len;
	}

	for ( uint16_t i = 0; i < frag_count; ++i ) {
		if ( !a->received[i] )
			return 0;
	}

	const size_t last_len = a->last_frag_len ? a->last_frag_len : CONN_FRAGMENT_DATA_SIZE;
	const size_t total_len = (size_t) ( frag_count - 1u ) * CONN_FRAGMENT_DATA_SIZE + last_len;

	if ( total_len > size ) {
		LOGE( "Receive buffer too small for assembled message: msg=%u payload=%zu buffer=%zu", msg_id, total_len, size );
		remove_assembly( a );
		return -1;
	}

	size_t pos = 0;
	for ( uint16_t i = 0; i < frag_count; ++i ) {
		const size_t part_len = ( i == frag_count - 1u ) ? last_len : (size_t) CONN_FRAGMENT_DATA_SIZE;

		memcpy( (uint8_t*) buf + pos, a->data + (size_t) i * CONN_FRAGMENT_DATA_SIZE, part_len );
		pos += part_len;
	}

	if ( sender )
		*sender = c;

	remove_assembly( a );
	return (int) pos;
}
