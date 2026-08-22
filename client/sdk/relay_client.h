#ifndef RELAY_CLIENT_H
#define RELAY_CLIENT_H

#include <stddef.h>
#include <stdint.h>
#include "relay_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RELAY_PUBKEY_HEX_LEN 64
#define RELAY_MAX_MSGS 10

typedef struct RelayClient RelayClient;
typedef struct RelayChat   RelayChat;
typedef struct RelayMsg	   RelayMsg;

typedef struct RelayCallbacks
{
	void ( *on_status )( RelayClient* client, const char* status, void* user );
	void ( *on_message )( RelayClient* client, const char* from_display, const char* text, void* user );
	void ( *on_e2e )( RelayClient* client, const char* display_name, int established, void* user );
	void ( *on_disconnect )( RelayClient* client, void* user );
} RelayCallbacks;

typedef struct RelayConfig
{
	const char*	   storage_dir;
	RelayCallbacks callbacks;
	void*		   user;
} RelayConfig;

int	 relay_client_create( RelayClient** out, const RelayConfig* cfg );
void relay_client_destroy( RelayClient* client );

int	 relay_client_connect( RelayClient* client, const char* host, uint16_t port );
int	 relay_client_load_account( RelayClient* c );
int	 relay_client_login( RelayClient* client, const char* handle, const char* display_name, char* err, size_t errcap );
int	 relay_client_login_saved( RelayClient* c, char* err, size_t errcap );
void relay_client_disconnect( RelayClient* client );

int	 relay_client_start( RelayClient* client );
void relay_client_stop( RelayClient* client );

int relay_client_poll( RelayClient* client, int timeout_ms );

int relay_client_open_chat( RelayClient* client, const char* handle );
int relay_client_next_chat( RelayClient* client );
int relay_client_set_active_chat( RelayClient* client, const char* handle );

int relay_client_send_active( RelayClient* client, const char* text );
int relay_client_send( RelayClient* client, const char* handle, const char* text );

void relay_client_lock( RelayClient* client );
void relay_client_unlock( RelayClient* client );

const RelayChat* relay_client_chats( RelayClient* client );
const RelayChat* relay_client_active_chat( RelayClient* client );
const char*		 relay_client_status( RelayClient* client );
const char*		 relay_client_nick( RelayClient* client );
const char*		 relay_client_handle( RelayClient* client );
const char*		 relay_client_id( RelayClient* client );
int				 relay_client_is_connected( RelayClient* client );
int				 relay_client_is_running( RelayClient* client );

const RelayChat* relay_chat_next( const RelayChat* chat );
const char*		 relay_chat_nick( const RelayChat* chat );
const char*		 relay_chat_handle( const RelayChat* chat );
const char*		 relay_chat_id( const RelayChat* chat );
const char*		 relay_chat_display_name( const RelayChat* chat );
int				 relay_chat_unread( const RelayChat* chat );
int				 relay_chat_msg_count( const RelayChat* chat );
int				 relay_chat_e2e_established( const RelayChat* chat );
const RelayMsg*	 relay_chat_messages( const RelayChat* chat );

const RelayMsg* relay_msg_next( const RelayMsg* msg );
const char*		relay_msg_from( const RelayMsg* msg );
const char*		relay_msg_text( const RelayMsg* msg );

#ifdef __cplusplus
}
#endif

#endif
