#ifndef EVCONNECTION_H
#define EVCONNECTION_H

#include <ev.h>
#include <ares.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>

#ifndef cwarn
#define cwarn(fmt, ...)   do{ \
	fprintf(stderr, "[WARN] %s:%d: ", __FILE__, __LINE__); \
	fprintf(stderr, fmt, ##__VA_ARGS__); \
	if (fmt[strlen(fmt) - 1] != 0x0a) { fprintf(stderr, "\n"); } \
	} while(0)
#endif

#ifndef likely
#define likely(x) __builtin_expect((x),1)
#define unlikely(x) __builtin_expect((x),0)
#endif

#define IOMAX ARES_GETSOCK_MAXNUM

typedef struct {
	ev_io io;
	int   id;
} io_ptr;

typedef enum {
	INITIAL = 0,
	RESOLVING,
	CONNECTING,
	CONNECTED,
	DISCONNECTING,
	DISCONNECTED,
	RECONNECTING
} CnnState;

typedef (*c_cb_err_t)(void *, int);
typedef (*c_cb_conn_t)(void *, struct sockaddr *);
typedef (*c_cb_read_t)(void *, size_t);

typedef struct {
	ev_io    rw;
	ev_io    ww;
	ev_timer tw;
	
	CnnState state;
	CnnState pstate;
	struct ev_loop * loop;
	
	
	char     *host;
	short int port;
	char      ipv4;
	char      ipv6;
	
	struct addrinfo *ai; // current pointer
	struct addrinfo *ai_top; // top pointer
	
	struct {
		int i;
		int c;
		struct addrinfo * addr[16];
	} ai1;
	
	
	struct sockaddr    addrs[16];
	int                addrc;
	int                addri;
	
	time_t             now;
	
	int   sock; // from io?
	
	// params
	double reconnect;
	double connect_timeout;
	double rw_timeout;
	
	c_cb_conn_t on_connected;
	c_cb_err_t  on_disconnect;
	c_cb_err_t  on_connfail;
	c_cb_read_t on_read;
	
	// read/write
	struct iovec *iov;
	int           iovcnt;
	int           iovuse;
	
	struct iovec *wbuf;
	int           wuse;
	int           wlen;
	int           wnow;
	
	char * rbuf;
	size_t ruse;
	size_t rlen;
	
	//dns
	struct {
		io_ptr     ios[IOMAX];
		int        ioc;
		ev_timer   tw;
		struct ev_loop * loop;
		struct {
			ares_channel channel;
			struct ares_options options;
		} ares;
		struct timeval timeout;
		struct in_addr       ip[16];
		int                  ipc;
		struct ares_in6_addr ip6[4];
		int                  ip6c;
		time_t               expire;
	} dns;
} ev_cnn;

void ev_cnn_init(ev_cnn *self);
void ev_cnn_clean(ev_cnn *self);

void do_connect(ev_cnn * self);
void do_write(ev_cnn *self, char *buf, size_t len);

#endif