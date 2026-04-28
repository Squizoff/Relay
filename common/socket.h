#ifndef SOCKET_WRAPPER_H
#define SOCKET_WRAPPER_H

#include <stdio.h>
#include <string.h>

#if defined( _DEBUG )
# define SW_LOG( fmt, ... ) Com_Printf( "[SOCKET_WRAPPER] " fmt "\n", ##__VA_ARGS__ )
#else
# define SW_LOG( fmt, ... )                                                                                                                          \
	 do {                                                                                                                                            \
	 } while ( 0 )
#endif

#if defined( _WIN32 )
# include <winsock2.h>
# include <ws2tcpip.h>
typedef SOCKET sock_t;
typedef int	   socklen_t;

# if !defined( __MINGW32__ ) && !defined( _SSIZE_T_DEFINED )
typedef int ssize_t;
#  define _SSIZE_T_DEFINED
# endif

static inline void socket_init( void )
{
	WSADATA wsaData;
	if ( WSAStartup( MAKEWORD( 2, 2 ), &wsaData ) != 0 ) {
		fprintf( stderr, "WSAStartup failed\n" );
		exit( EXIT_FAILURE );
	}
}

static inline void socket_cleanup( void )
{
	WSACleanup();
}

static inline int wrap_inet_pton( int af, const char* src, void* dst )
{
	if ( !src || !dst )
		return 0;

	if ( af == AF_INET ) {
		unsigned long addr = inet_addr( src );
		if ( addr == INADDR_NONE )
			return 0;
		*(struct in_addr*) dst = *(struct in_addr*) &addr;
		return 1;
	} else if ( af == AF_INET6 ) {
		struct in6_addr ipv6;
		if ( InetPtonA( AF_INET6, src, &ipv6 ) != 1 ) {
			return 0;
		}
		*(struct in6_addr*) dst = ipv6;
		return 1;
	}

	return -1; // unsupported family
}

static inline const char* wrap_inet_ntop( int af, const void* src, char* dst, socklen_t size )
{
	if ( !src || !dst || size <= 0 )
		return NULL;
	if ( af == AF_INET ) {
		return InetNtopA( AF_INET, (PVOID) src, dst, size );
	} else if ( af == AF_INET6 ) {
		return InetNtopA( AF_INET6, (PVOID) src, dst, size );
	}
	return NULL;
}

# define inet_ntop wrap_inet_ntop
# define inet_pton wrap_inet_pton

# define INVALID_SOCK INVALID_SOCKET
# define IS_INVALID_SOCKET( s ) ( ( s ) == INVALID_SOCKET )
# define IS_SOCKET_ERROR( r ) ( ( r ) == SOCKET_ERROR )

# ifndef SO_REUSEPORT
#  define SO_REUSEPORT -2
# endif

#else
# include <arpa/inet.h>
# include <errno.h>
# include <netinet/in.h>
# include <sys/ioctl.h>
# include <sys/socket.h>
# include <sys/types.h>
# include <unistd.h>

typedef int sock_t;
# define INVALID_SOCK -1
# define IS_INVALID_SOCKET( s ) ( ( s ) < 0 )
# define IS_SOCKET_ERROR( r ) ( ( r ) < 0 )

static inline void socket_init( void )
{
}
static inline void socket_cleanup( void )
{
}

#endif

#if defined( _WIN32 )
# define s_errno WSAGetLastError()
#else
# define s_errno errno
#endif

// --- safe strerror ---
static inline char* socket_error( void )
{
	static char buf[256];
	int			err = s_errno;
	buf[0] = '\0';

#if defined( _WIN32 )
	DWORD len = FormatMessageA( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, (DWORD) err,
		MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ), buf, sizeof( buf ), NULL );
	if ( len == 0 ) {
		snprintf( buf, sizeof( buf ), "Unknown error %d", err );
		buf[sizeof( buf ) - 1] = '\0';
	}

#else // POSIX
# if defined( __GLIBC__ ) && defined( _GNU_SOURCE )
	char* msg = strerror_r( err, buf, sizeof( buf ) );
	if ( msg != buf ) {
		strncpy( buf, msg, sizeof( buf ) );
		buf[sizeof( buf ) - 1] = '\0';
	}
# else
	if ( strerror_r( err, buf, sizeof( buf ) ) != 0 ) {
		snprintf( buf, sizeof( buf ), "Unknown error %d", err );
		buf[sizeof( buf ) - 1] = '\0';
	}
# endif
#endif

	return buf;
}

// --- SAFE WRAPPERS ---

static inline sock_t wrap_socket( int domain, int type, int protocol )
{
	sock_t s = socket( domain, type, protocol );
	if ( IS_INVALID_SOCKET( s ) ) {
		SW_LOG( "socket error: %s", socket_error() );
	}
	return s;
}

static inline int wrap_bind( sock_t sockfd, const struct sockaddr* addr, socklen_t addrlen )
{
	if ( IS_INVALID_SOCKET( sockfd ) || !addr || addrlen <= 0 ) {
		SW_LOG( "bind: invalid arguments" );
		return -1;
	}
	int r = bind( sockfd, addr, (int) addrlen );
	if ( IS_SOCKET_ERROR( r ) ) {
		SW_LOG( "bind error: %s", socket_error() );
	}
	return r;
}

static inline int wrap_listen( sock_t sockfd, int backlog )
{
	if ( IS_INVALID_SOCKET( sockfd ) || backlog < 0 ) {
		SW_LOG( "listen: invalid arguments" );
		return -1;
	}
	int r = listen( sockfd, backlog );
	if ( IS_SOCKET_ERROR( r ) ) {
		SW_LOG( "listen error: %s", socket_error() );
	}
	return r;
}

static inline sock_t wrap_accept( sock_t sockfd, struct sockaddr* addr, socklen_t* addrlen )
{
	if ( IS_INVALID_SOCKET( sockfd ) ) {
		SW_LOG( "accept: invalid socket" );
		return INVALID_SOCK;
	}
	sock_t c = accept( sockfd, addr, addrlen );
	if ( IS_INVALID_SOCKET( c ) ) {
		SW_LOG( "accept error: %s", socket_error() );
	}
	return c;
}

static inline int wrap_connect( sock_t sockfd, const struct sockaddr* addr, socklen_t addrlen )
{
	if ( IS_INVALID_SOCKET( sockfd ) || !addr || addrlen <= 0 ) {
		SW_LOG( "connect: invalid arguments" );
		return -1;
	}
	int r = connect( sockfd, addr, (int) addrlen );
	if ( IS_SOCKET_ERROR( r ) ) {
		SW_LOG( "connect error: %s", socket_error() );
	}
	return r;
}

static inline int wrap_close( sock_t sockfd )
{
	if ( IS_INVALID_SOCKET( sockfd ) ) {
		SW_LOG( "close: invalid socket" );
		return -1;
	}
#if defined( _WIN32 )
	int r = closesocket( sockfd );
#else
	int r = close( sockfd );
#endif
	if ( IS_SOCKET_ERROR( r ) ) {
		SW_LOG( "close error: %s", socket_error() );
	}
	return r;
}

static inline ssize_t wrap_read( sock_t sockfd, void* buf, size_t count )
{
	if ( IS_INVALID_SOCKET( sockfd ) || !buf || count == 0 ) {
		SW_LOG( "read: invalid arguments" );
		return -1;
	}
#if defined( _WIN32 )
	if ( count > INT_MAX )
		count = INT_MAX;
	int n = recv( sockfd, (char*) buf, (int) count, 0 );
#else
	ssize_t n = read( sockfd, buf, count );
#endif
	if ( IS_SOCKET_ERROR( n ) ) {
		SW_LOG( "read error: %s", socket_error() );
	}
	return n;
}

static inline ssize_t wrap_write( sock_t sockfd, const void* buf, size_t count )
{
	if ( IS_INVALID_SOCKET( sockfd ) || !buf || count == 0 ) {
		SW_LOG( "write: invalid arguments" );
		return -1;
	}
#if defined( _WIN32 )
	if ( count > INT_MAX )
		count = INT_MAX;
	int n = send( sockfd, (const char*) buf, (int) count, 0 );
#else
	ssize_t n = write( sockfd, buf, count );
#endif
	if ( IS_SOCKET_ERROR( n ) ) {
		SW_LOG( "write error: %s", socket_error() );
	}
	return n;
}

static inline int wrap_setsockopt( sock_t sockfd, int level, int optname, const void* optval, socklen_t optlen )
{
	if ( IS_INVALID_SOCKET( sockfd ) || !optval || optlen <= 0 ) {
		SW_LOG( "setsockopt: invalid arguments" );
		return -1;
	}
#if defined( _WIN32 )
	if ( optname == SO_REUSEPORT )
		return 0;
	return setsockopt( sockfd, level, optname, (const char*) optval, (int) optlen );
#else
	return setsockopt( sockfd, level, optname, optval, optlen );
#endif
}

static inline ssize_t wrap_send( sock_t sockfd, const void* buf, size_t len, int flags )
{
	if ( IS_INVALID_SOCKET( sockfd ) || !buf || len == 0 ) {
		SW_LOG( "send: invalid arguments" );
		return -1;
	}
#if defined( _WIN32 )
	if ( len > INT_MAX )
		len = INT_MAX;
	int n = send( sockfd, (const char*) buf, (int) len, flags );
#else
	ssize_t n = send( sockfd, buf, len, flags );
#endif
	if ( IS_SOCKET_ERROR( n ) ) {
		SW_LOG( "send error: %s", socket_error() );
	}
	return n;
}

static inline ssize_t wrap_recv( sock_t sockfd, void* buf, size_t len, int flags )
{
	if ( IS_INVALID_SOCKET( sockfd ) || !buf || len == 0 ) {
		SW_LOG( "recv: invalid arguments" );
		return -1;
	}
#if defined( _WIN32 )
	if ( len > INT_MAX )
		len = INT_MAX;
	int n = recv( sockfd, (char*) buf, (int) len, flags );
#else
	ssize_t n = recv( sockfd, buf, len, flags );
#endif
	if ( IS_SOCKET_ERROR( n ) ) {
		SW_LOG( "recv error: %s", socket_error() );
	}
	return n;
}

static inline ssize_t wrap_sendto( sock_t sockfd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen )
{
	if ( IS_INVALID_SOCKET( sockfd ) || !buf || len == 0 || !dest_addr || addrlen <= 0 ) {
		SW_LOG( "sendto: invalid arguments" );
		return -1;
	}
#if defined( _WIN32 )
	if ( len > INT_MAX )
		len = INT_MAX;
	int n = sendto( sockfd, (const char*) buf, (int) len, flags, dest_addr, addrlen );
#else
	ssize_t n = sendto( sockfd, buf, len, flags, dest_addr, addrlen );
#endif
	if ( IS_SOCKET_ERROR( n ) ) {
		SW_LOG( "sendto error: %s", socket_error() );
	}
	return n;
}

static inline ssize_t wrap_recvfrom( sock_t sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen )
{
	if ( IS_INVALID_SOCKET( sockfd ) || !buf || len == 0 ) {
		SW_LOG( "recvfrom: invalid arguments" );
		return -1;
	}
#if defined( _WIN32 )
	if ( len > INT_MAX )
		len = INT_MAX;
	int n = recvfrom( sockfd, (char*) buf, (int) len, flags, src_addr, addrlen );
#else
	ssize_t n = recvfrom( sockfd, buf, len, flags, src_addr, addrlen );
#endif
	if ( IS_SOCKET_ERROR( n ) ) {
		SW_LOG( "recvfrom error: %s", socket_error() );
	}
	return n;
}

static inline int wrap_ioctl( sock_t sockfd, unsigned long cmd, void* argp )
{
	if ( IS_INVALID_SOCKET( sockfd ) || !argp ) {
		SW_LOG( "wrap_ioctl: invalid arguments" );
		return -1;
	}

#if defined( _WIN32 )
	int r = ioctlsocket( sockfd, cmd, (u_long*) argp );
	if ( r != 0 ) {
		SW_LOG( "wrap_ioctl (Windows) error: %s", socket_error() );
		return -1;
	}
#else
	int r = ioctl( sockfd, cmd, argp );
	if ( r < 0 ) {
		SW_LOG( "wrap_ioctl (Linux) error: %s", socket_error() );
		return -1;
	}
#endif

	return 0;
}

#define socket wrap_socket
#define bind wrap_bind
#define listen wrap_listen
#define accept wrap_accept
#define connect wrap_connect
#define read wrap_read
#define write wrap_write
#define close wrap_close
#define setsockopt wrap_setsockopt
#define sendto wrap_sendto
#define recvfrom wrap_recvfrom
#define send wrap_send
#define recv wrap_recv
#define ioctl wrap_ioctl

#endif // SOCKET_WRAPPER_H
