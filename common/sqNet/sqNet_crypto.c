#include "sqNet_internal.h"
#include <limits.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#define SQOBF_IMPLEMENTATION
#include "sqobf.h"

#define CONN_PLAIN_LEN_SIZE ( (size_t) sizeof( uint16_t ) )
#define OPENSSL_KEY_SIZE 32u
#define OPENSSL_NONCE_SIZE 12u
#define SQNET_X25519_KEY_SIZE 32u

static int sqnet_bytes_all_zero( const uint8_t* data, size_t len )
{
	size_t	i;
	uint8_t acc = 0;

	if ( !data )
		return 1;

	for ( i = 0; i < len; ++i )
		acc |= data[i];

	return acc == 0;
}

static size_t round_up_pow2_bucket( size_t v )
{
	size_t bucket = 32u;

	if ( v == 0 )
		return bucket;

	while ( bucket < v ) {
		if ( bucket > ( SIZE_MAX >> 1 ) )
			return 0;
		bucket <<= 1;
	}

	return bucket;
}

static void derive_openssl_material( const uint32_t session_key[SESSION_KEY_WORDS], uint32_t session_secret, uint64_t iv, uint64_t ts_ms,
	uint8_t out_key[OPENSSL_KEY_SIZE], uint8_t out_nonce[OPENSSL_NONCE_SIZE] )
{
	uint8_t	 seed[( SESSION_KEY_WORDS * sizeof( uint32_t ) ) + sizeof( uint32_t ) + sizeof( uint64_t ) * 2];
	size_t	 off = 0;
	uint64_t iv_be = htonll( iv );
	uint64_t ts_be = htonll( ts_ms );
	uint32_t session_secret_be = htonl( session_secret );

	for ( uint32_t i = 0; i < SESSION_KEY_WORDS; ++i ) {
		uint32_t w_be = htonl( session_key[i] );
		memcpy( seed + off, &w_be, sizeof( w_be ) );
		off += sizeof( w_be );
	}
	memcpy( seed + off, &session_secret_be, sizeof( session_secret_be ) );
	off += sizeof( session_secret_be );
	memcpy( seed + off, &iv_be, sizeof( iv_be ) );
	off += sizeof( iv_be );
	memcpy( seed + off, &ts_be, sizeof( ts_be ) );
	off += sizeof( ts_be );

	EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id( EVP_PKEY_HKDF, NULL );
	if ( !pctx )
		goto fail;

	if ( EVP_PKEY_derive_init( pctx ) <= 0 )
		goto fail;

	if ( EVP_PKEY_CTX_set_hkdf_md( pctx, EVP_sha256() ) <= 0 )
		goto fail;

	if ( EVP_PKEY_CTX_set1_hkdf_key( pctx, seed, off ) <= 0 )
		goto fail;

	uint8_t info_key[] = { 0xA3 };
	if ( EVP_PKEY_CTX_add1_hkdf_info( pctx, info_key, sizeof( info_key ) ) <= 0 )
		goto fail;
	size_t out_len = OPENSSL_KEY_SIZE;
	if ( EVP_PKEY_derive( pctx, out_key, &out_len ) <= 0 || out_len != OPENSSL_KEY_SIZE )
		goto fail;

	uint8_t info_nonce[] = { 0x5C };
	if ( EVP_PKEY_CTX_add1_hkdf_info( pctx, info_nonce, sizeof( info_nonce ) ) <= 0 )
		goto fail;
	out_len = OPENSSL_NONCE_SIZE;
	if ( EVP_PKEY_derive( pctx, out_nonce, &out_len ) <= 0 || out_len != OPENSSL_NONCE_SIZE )
		goto fail;

	EVP_PKEY_CTX_free( pctx );
	return;

fail:
	memset( out_key, 0, OPENSSL_KEY_SIZE );
	memset( out_nonce, 0, OPENSSL_NONCE_SIZE );
	if ( pctx )
		EVP_PKEY_CTX_free( pctx );
}

int sqnet_generate_x25519_keypair( uint8_t out_public[32], uint8_t out_private[32] )
{
	EVP_PKEY_CTX* pctx = NULL;
	EVP_PKEY*	  pkey = NULL;
	size_t		  pub_len = SQNET_X25519_KEY_SIZE;
	size_t		  priv_len = SQNET_X25519_KEY_SIZE;
	int			  ok = 0;

	if ( !out_public || !out_private )
		return -1;

	pctx = EVP_PKEY_CTX_new_id( EVP_PKEY_X25519, NULL );
	if ( !pctx )
		goto cleanup;
	if ( EVP_PKEY_keygen_init( pctx ) != 1 )
		goto cleanup;
	if ( EVP_PKEY_keygen( pctx, &pkey ) != 1 )
		goto cleanup;
	if ( EVP_PKEY_get_raw_public_key( pkey, out_public, &pub_len ) != 1 || pub_len != SQNET_X25519_KEY_SIZE )
		goto cleanup;
	if ( EVP_PKEY_get_raw_private_key( pkey, out_private, &priv_len ) != 1 || priv_len != SQNET_X25519_KEY_SIZE )
		goto cleanup;

	ok = 1;

cleanup:
	if ( !ok ) {
		memset( out_public, 0, SQNET_X25519_KEY_SIZE );
		memset( out_private, 0, SQNET_X25519_KEY_SIZE );
	}
	if ( pkey )
		EVP_PKEY_free( pkey );
	if ( pctx )
		EVP_PKEY_CTX_free( pctx );
	return ok ? 0 : -1;
}

int sqnet_x25519_shared_secret( const uint8_t private_key[32], const uint8_t peer_public[32], uint8_t out_shared[32] )
{
	EVP_PKEY*	  priv = NULL;
	EVP_PKEY*	  peer = NULL;
	EVP_PKEY_CTX* ctx = NULL;
	size_t		  shared_len = SQNET_X25519_KEY_SIZE;
	int			  ok = 0;

	if ( !private_key || !peer_public || !out_shared )
		return -1;

	priv = EVP_PKEY_new_raw_private_key( EVP_PKEY_X25519, NULL, private_key, SQNET_X25519_KEY_SIZE );
	peer = EVP_PKEY_new_raw_public_key( EVP_PKEY_X25519, NULL, peer_public, SQNET_X25519_KEY_SIZE );
	if ( !priv || !peer )
		goto cleanup;

	ctx = EVP_PKEY_CTX_new( priv, NULL );
	if ( !ctx )
		goto cleanup;
	if ( EVP_PKEY_derive_init( ctx ) != 1 )
		goto cleanup;
	if ( EVP_PKEY_derive_set_peer( ctx, peer ) != 1 )
		goto cleanup;
	if ( EVP_PKEY_derive( ctx, out_shared, &shared_len ) != 1 || shared_len != SQNET_X25519_KEY_SIZE )
		goto cleanup;
	if ( sqnet_bytes_all_zero( out_shared, SQNET_X25519_KEY_SIZE ) )
		goto cleanup;

	ok = 1;

cleanup:
	if ( !ok )
		memset( out_shared, 0, SQNET_X25519_KEY_SIZE );
	if ( ctx )
		EVP_PKEY_CTX_free( ctx );
	if ( peer )
		EVP_PKEY_free( peer );
	if ( priv )
		EVP_PKEY_free( priv );
	return ok ? 0 : -1;
}

int openssl_payload_pass( uint8_t* data, size_t data_len, const uint32_t session_key[SESSION_KEY_WORDS], uint32_t session_secret, uint64_t iv,
	uint64_t ts_ms, uint8_t tag[CONN_TAG_SIZE], int encrypt )
{
	EVP_CIPHER_CTX* ctx = NULL;
	uint8_t			key[OPENSSL_KEY_SIZE];
	uint8_t			nonce[OPENSSL_NONCE_SIZE];
	uint8_t			aad[CONN_IV_SIZE + CONN_TIME_SIZE];
	int				ok = 0;

	uint64_t iv_be = htonll( iv );
	uint64_t ts_be = htonll( ts_ms );

	if ( !data || !tag || data_len == 0 || data_len > (size_t) INT_MAX )
		return -1;

	derive_openssl_material( session_key, session_secret, iv, ts_ms, key, nonce );

	memcpy( aad, &iv_be, sizeof( iv_be ) );
	memcpy( aad + sizeof( iv_be ), &ts_be, sizeof( ts_be ) );

	ctx = EVP_CIPHER_CTX_new();
	if ( !ctx ) {
		LOGE( "EVP_CIPHER_CTX_new failed" );
		goto cleanup;
	}

	int len = 0;
	int total = 0;

	if ( encrypt ) {
		if ( EVP_EncryptInit_ex( ctx, EVP_aes_256_gcm(), NULL, NULL, NULL ) != 1 ) {
			LOGE( "EVP_EncryptInit_ex failed" );
			goto cleanup;
		}
		if ( EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_GCM_SET_IVLEN, OPENSSL_NONCE_SIZE, NULL ) != 1 ) {
			LOGE( "EVP_CTRL_GCM_SET_IVLEN failed" );
			goto cleanup;
		}
		if ( EVP_EncryptInit_ex( ctx, NULL, NULL, key, nonce ) != 1 ) {
			LOGE( "EVP_EncryptInit_ex(key/nonce) failed" );
			goto cleanup;
		}

		if ( EVP_EncryptUpdate( ctx, NULL, &len, aad, sizeof( aad ) ) != 1 ) {
			LOGE( "EVP_EncryptUpdate(AAD) failed" );
			goto cleanup;
		}

		if ( EVP_EncryptUpdate( ctx, data, &len, data, (int) data_len ) != 1 ) {
			LOGE( "EVP_EncryptUpdate failed" );
			goto cleanup;
		}
		total += len;

		if ( EVP_EncryptFinal_ex( ctx, data + total, &len ) != 1 ) {
			LOGE( "EVP_EncryptFinal_ex failed" );
			goto cleanup;
		}
		total += len;

		if ( EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_GCM_GET_TAG, CONN_TAG_SIZE, tag ) != 1 ) {
			LOGE( "EVP_CTRL_GCM_GET_TAG failed" );
			goto cleanup;
		}

	} else {
		if ( EVP_DecryptInit_ex( ctx, EVP_aes_256_gcm(), NULL, NULL, NULL ) != 1 ) {
			LOGE( "EVP_DecryptInit_ex failed" );
			goto cleanup;
		}
		if ( EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_GCM_SET_IVLEN, OPENSSL_NONCE_SIZE, NULL ) != 1 ) {
			LOGE( "EVP_CTRL_GCM_SET_IVLEN failed" );
			goto cleanup;
		}
		if ( EVP_DecryptInit_ex( ctx, NULL, NULL, key, nonce ) != 1 ) {
			LOGE( "EVP_DecryptInit_ex(key/nonce) failed" );
			goto cleanup;
		}

		if ( EVP_DecryptUpdate( ctx, NULL, &len, aad, sizeof( aad ) ) != 1 ) {
			LOGE( "EVP_DecryptUpdate(AAD) failed" );
			goto cleanup;
		}

		if ( EVP_DecryptUpdate( ctx, data, &len, data, (int) data_len ) != 1 ) {
			LOGE( "EVP_DecryptUpdate failed" );
			goto cleanup;
		}
		total += len;

		if ( EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_GCM_SET_TAG, CONN_TAG_SIZE, tag ) != 1 ) {
			LOGE( "EVP_CTRL_GCM_SET_TAG failed" );
			goto cleanup;
		}

		if ( EVP_DecryptFinal_ex( ctx, data + total, &len ) != 1 ) {
			LOGE( "EVP_DecryptFinal_ex failed" );
			goto cleanup;
		}
		total += len;
	}

	ok = 1;

cleanup:
	if ( ctx )
		EVP_CIPHER_CTX_free( ctx );
	memset( key, 0, sizeof( key ) );
	memset( nonce, 0, sizeof( nonce ) );
	memset( aad, 0, sizeof( aad ) );

	return ok ? 0 : -1;
}

uint32_t compute_hash( const uint8_t* data, size_t len, uint32_t secret )
{
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int  digest_len = 0;
	unsigned char key[8];
	uint32_t	  v;

	key[0] = (unsigned char) ( secret >> 24 );
	key[1] = (unsigned char) ( secret >> 16 );
	key[2] = (unsigned char) ( secret >> 8 );
	key[3] = (unsigned char) ( secret & 0xFFu );
	key[4] = 0xA3u;
	key[5] = 0x5Cu;
	key[6] = 0x19u;
	key[7] = 0xE7u;

	HMAC( EVP_sha256(), key, (int) sizeof( key ), data, len, digest, &digest_len );

	v = ( (uint32_t) digest[0] << 24 ) | ( (uint32_t) digest[1] << 16 ) | ( (uint32_t) digest[2] << 8 ) | (uint32_t) digest[3];

	memset( digest, 0, sizeof( digest ) );
	return v;
}

int compute_handshake_proof(
	const uint8_t shared_secret[32], uint64_t client_nonce, uint64_t server_nonce, uint64_t client_id, uint8_t role_tag, uint8_t out_proof[32] )
{
	uint8_t		 material[1 + ( sizeof( uint64_t ) * 3 ) + 11];
	uint8_t		 digest[SHA256_DIGEST_LENGTH];
	unsigned int dlen = 0;
	uint64_t	 client_nonce_be = htonll( client_nonce );
	uint64_t	 server_nonce_be = htonll( server_nonce );
	uint64_t	 client_id_be = htonll( client_id );
	size_t		 off = 0;

	if ( !shared_secret || !out_proof )
		return -1;

	material[off++] = role_tag;
	memcpy( material + off, &client_nonce_be, sizeof( client_nonce_be ) );
	off += sizeof( client_nonce_be );
	memcpy( material + off, &server_nonce_be, sizeof( server_nonce_be ) );
	off += sizeof( server_nonce_be );
	memcpy( material + off, &client_id_be, sizeof( client_id_be ) );
	off += sizeof( client_id_be );
	memcpy( material + off, "SQNET-HS-V1", 11 );
	off += 11;

	if ( !HMAC( EVP_sha256(), shared_secret, SQNET_X25519_KEY_SIZE, material, off, digest, &dlen ) || dlen != 32 ) {
		memset( out_proof, 0, 32 );
		memset( digest, 0, sizeof( digest ) );
		memset( material, 0, sizeof( material ) );
		return -1;
	}

	memcpy( out_proof, digest, 32 );
	memset( digest, 0, sizeof( digest ) );
	memset( material, 0, sizeof( material ) );
	return 0;
}

void derive_session_keys(
	const uint8_t shared_secret[32], uint64_t client_nonce, uint64_t server_nonce, uint32_t out_key[SESSION_KEY_WORDS], uint32_t* out_secret )
{
	uint8_t	 material[16 + 18];
	size_t	 off = 0;
	uint64_t s_be = htonll( server_nonce );
	uint64_t c_be = htonll( client_nonce );
	memcpy( material + off, &s_be, sizeof( s_be ) );
	off += sizeof( s_be );
	memcpy( material + off, &c_be, sizeof( c_be ) );
	off += sizeof( c_be );
	memcpy( material + off, "SQNET-SESSION-KDF-V1", 18 );
	off += 18;

	EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id( EVP_PKEY_HKDF, NULL );
	if ( !pctx )
		goto fail;

	if ( EVP_PKEY_derive_init( pctx ) <= 0 )
		goto fail;
	if ( EVP_PKEY_CTX_set_hkdf_md( pctx, EVP_sha256() ) <= 0 )
		goto fail;
	if ( EVP_PKEY_CTX_set1_hkdf_salt( pctx, NULL, 0 ) <= 0 )
		goto fail;
	if ( EVP_PKEY_CTX_set1_hkdf_key( pctx, shared_secret, 32 ) <= 0 )
		goto fail;
	if ( EVP_PKEY_CTX_add1_hkdf_info( pctx, material, off ) <= 0 )
		goto fail;

	uint8_t out[SESSION_KEY_WORDS * 4 + 4];
	size_t	out_len = sizeof( out );
	if ( EVP_PKEY_derive( pctx, out, &out_len ) <= 0 )
		goto fail;

	for ( size_t i = 0; i < SESSION_KEY_WORDS; ++i )
		out_key[i] = (uint32_t) ( out[i * 4] << 24 | out[i * 4 + 1] << 16 | out[i * 4 + 2] << 8 | out[i * 4 + 3] );

	*out_secret = (uint32_t) ( out[SESSION_KEY_WORDS * 4] << 24 | out[SESSION_KEY_WORDS * 4 + 1] << 16 | out[SESSION_KEY_WORDS * 4 + 2] << 8
		| out[SESSION_KEY_WORDS * 4 + 3] );

	EVP_PKEY_CTX_free( pctx );
	return;

fail:
	memset( out_key, 0, sizeof( uint32_t ) * SESSION_KEY_WORDS );
	*out_secret = 0;
	if ( pctx )
		EVP_PKEY_CTX_free( pctx );
}

int send_encrypted_payload(
	Conn* conn, const uint32_t key[32], uint32_t secret_key, const uint8_t* payload, size_t payload_len, const struct sockaddr_in* addr )
{
	size_t	   plain_with_len;
	size_t	   base_total_len;
	size_t	   target_total_len;
	size_t	   padded_payload_len;
	size_t	   pad_len;
	size_t	   total_len;
	uint8_t*   encrypted_data;
	uint64_t   iv;
	uint64_t   ts_ms;
	uint8_t	   tag[CONN_TAG_SIZE];
	int		   out_rc;
	int		   out_fd = -1;
	sqobf_ctx* ctx1 = NULL;

	if ( !conn || !payload || payload_len == 0 || payload_len > (size_t) UINT16_MAX )
		return -1;

	plain_with_len = CONN_PLAIN_LEN_SIZE + payload_len;
	base_total_len = CONN_OVERHEAD_SIZE + plain_with_len;
	target_total_len = round_up_pow2_bucket( base_total_len );
	if ( target_total_len == 0 || target_total_len < base_total_len || target_total_len > SQNET_MAX_PACKET_SIZE )
		return -1;

	padded_payload_len = target_total_len - CONN_OVERHEAD_SIZE;
	if ( padded_payload_len > CONN_MAX_DATA_SIZE || padded_payload_len < plain_with_len )
		return -1;

	pad_len = padded_payload_len - plain_with_len;
	total_len = target_total_len;

	encrypted_data = (uint8_t*) malloc( total_len );
	if ( !encrypted_data ) {
		LOGE( "Memory allocation failed for encryption" );
		return -1;
	}

	if ( RAND_bytes( (unsigned char*) &iv, sizeof( iv ) ) != 1 ) {
		LOGE( "RAND_bytes failed (IV)" );
		free( encrypted_data );
		return -1;
	}
	if ( iv == 0 )
		iv = 1;

	uint64_t iv_be = htonll( iv );
	memcpy( encrypted_data, &iv_be, sizeof( iv_be ) );

	ts_ms = now_ms();

	uint64_t ts_be = htonll( ts_ms );
	memcpy( encrypted_data + CONN_IV_SIZE, &ts_be, sizeof( ts_be ) );

	uint16_t plain_len_be = htons( (uint16_t) payload_len );
	memcpy( encrypted_data + CONN_PAYLOAD_OFFSET, &plain_len_be, sizeof( plain_len_be ) );

	memcpy( encrypted_data + CONN_PAYLOAD_OFFSET + CONN_PLAIN_LEN_SIZE, payload, payload_len );

	if ( pad_len > 0 ) {
		if ( RAND_bytes( encrypted_data + CONN_PAYLOAD_OFFSET + CONN_PLAIN_LEN_SIZE + payload_len, pad_len ) != 1 ) {
			LOGE( "RAND_bytes failed (padding)" );
			free( encrypted_data );
			return -1;
		}
	}

	ctx1 = sqobf_create( key, secret_key );
	if ( !ctx1 ) {
		LOGE( "sqobf_create failed (ctx1)" );
		free( encrypted_data );
		return -1;
	}

	if ( sqobf_setPos( ctx1, iv ) != 0 || sqobf_apply( ctx1, encrypted_data + CONN_PAYLOAD_OFFSET, padded_payload_len ) != 0 ) {
		LOGE( "sqobf apply failed (ctx1)" );
		sqobf_destroy( ctx1 );
		free( encrypted_data );
		return -1;
	}

	sqobf_destroy( ctx1 );

	memset( tag, 0, sizeof( tag ) );

	if ( openssl_payload_pass( encrypted_data + CONN_PAYLOAD_OFFSET, padded_payload_len, key, secret_key, iv, ts_ms, tag, 1 ) != 0 ) {
		LOGE( "OpenSSL encryption pass failed" );
		free( encrypted_data );
		return -1;
	}

	memcpy( encrypted_data + CONN_PAYLOAD_OFFSET + padded_payload_len, tag, sizeof( tag ) );
	memset( tag, 0, sizeof( tag ) );

	if ( conn->is_listener ) {
		Client* c = NULL;
		if ( addr )
			c = find_client( conn, addr );
		if ( !c || !is_socket_open( c->sockfd ) ) {
			free( encrypted_data );
			return -1;
		}
		out_fd = c->sockfd;
	} else {
		out_fd = conn->sockfd;
	}

	out_rc = sqnet_send_packet_fd( out_fd, encrypted_data, total_len );
	free( encrypted_data );

	if ( out_rc != 0 ) {
		LOGE( "sqnet_send_packet_fd failed: %s", socket_error() );
		return -1;
	}

	return 0;
}
