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

#ifndef cnntrace
#define cnntrace(cnn, fmt, ...) do { \
	if (unlikely((cnn)->trace > 0)) { \
		warn( "[TRC] %0.6f %s:%d: %p S:%s:%d " fmt "%s", ev_now(EV_DEFAULT), __FILE__, __LINE__, (cnn), strstate( ((ev_cnn*)cnn)->state ), ((ev_cnn*)cnn)->state, ##__VA_ARGS__, fmt[strlen(fmt) - 1] != 0x0a ? "\n" : "" ); \
	} \
} while (0)
#endif

#ifndef cwarn
#define cwarn(fmt, ...)   do{ \
	fprintf(stderr, "[WARN] %0.6f %s:%d: ", ev_now(EV_DEFAULT), __FILE__, __LINE__); \
	fprintf(stderr, fmt, ##__VA_ARGS__); \
	if (fmt[strlen(fmt) - 1] != 0x0a) { fprintf(stderr, "\n"); } \
	} while(0)
#endif

#ifndef warn
#define warn cwarn
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

const char * strstate( CnnState x );

typedef void (*c_cb_err_t)(void *, int);
typedef void (*c_cb_conn_t)(void *, struct sockaddr *);
typedef void (*c_cb_read_t)(void *, size_t);

typedef struct {
	ev_io    rw;
	ev_io    ww;
	ev_timer tw;

	CnnState state;
	CnnState pstate;
	struct ev_loop * loop;


	char     *host;
	short unsigned int port;
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
	
	int trace;
} ev_cnn;

void ev_cnn_init(ev_cnn *self);
void ev_cnn_clean(ev_cnn *self);

void do_connect(ev_cnn * self);
void do_disconnect(ev_cnn * self);

void do_write(ev_cnn *self, char *buf, size_t len);

void on_connect_reset(ev_cnn * self, int err);

void do_enable_rw_timer(ev_cnn * self);
void do_disable_rw_timer(ev_cnn * self);

#endif
