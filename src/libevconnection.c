#include <evconnection.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <fcntl.h>

#define dSELFby(ptr,xx) ev_cnn * self = (ev_cnn *) ( (char *) ptr - (ptrdiff_t) &((ev_cnn *) 0)-> xx );
#define set_state(newstate) do{ cnntrace(self,"switch state to %s:%d", strstate(newstate), newstate); self->state = newstate; } while(0)

// #define debug(...) cwarn(__VA_ARGS__)
#define debug(...)
#define memdup(a,b) memcpy(malloc(b),a,b)

static const struct addrinfo hints4 =
	{ AI_NUMERICHOST, AF_INET, SOCK_STREAM, IPPROTO_TCP };
static const struct addrinfo hints6 =
	{ AI_NUMERICHOST, AF_INET6, SOCK_STREAM, IPPROTO_TCP };


static void on_reconnect_timer( struct ev_loop *loop, ev_timer *w, int revents );
static void on_connect_timer ( struct ev_loop *loop, ev_timer *w, int revents );
static void on_rw_timer(  struct ev_loop *loop, ev_timer *w, int revents );

static void on_read_io( struct ev_loop *loop, ev_io *w, int revents );
static void on_connect_io( struct ev_loop *loop, ev_io *w, int revents );
static void on_write_io( struct ev_loop *loop, ev_io *w, int revents );

static void on_connect_failed(ev_cnn * self, int err);

static void _do_connect(ev_cnn * self);

static inline void _resolve_a(ev_cnn *self);
static inline void _resolve_aaaa(ev_cnn *self);
static inline void _resolve_ghbn(ev_cnn *self);

void do_enable_rw_timer(ev_cnn * self) {
	if (self->rw_timeout > 0) {
		debug("start timer %f",self->rw_timeout);
		ev_timer_start( self->loop,&self->tw );
	}
}

void do_disable_rw_timer(ev_cnn * self) {
	if (self->tw.active) {
		debug("stop timer %f",self->rw_timeout);
		ev_timer_stop( self->loop,&self->tw );
	}
}


static void ev_cnn_ns_state_cb(ev_cnn *self, int s, int read, int write) {
	struct timeval *tvp, tv;
	memset(&tv,0,sizeof(tv));
	if( !ev_is_active( &self->dns.tw ) && (tvp = ares_timeout(self->dns.ares.channel, NULL, &tv)) ) {
		double timeout = (double)tvp->tv_sec+(double)tvp->tv_usec/1.0e6;
		cwarn("Set timeout to %0.8lf for %d",timeout, s);
		if (timeout > 0) {
			//resolver->tw.interval = timeout;
			//ev_timer_again(resolver->loop, &eares->tw);
			ev_timer_set(&self->dns.tw,timeout,0.);
			ev_timer_start(self->loop, &self->dns.tw);
		}
	}
	//cwarn("Change state fd %d read:%d write:%d; max time: %zu.%zu (%p) (active: %d)", s, read, write, tv.tv_sec, tv.tv_usec, tvp, self->dns.ioc);
	int i;
	io_ptr * iop_new = 0, * iop_old = 0, *iop;
	for (i=0; i<IOMAX; i++) {
		if ( self->dns.ios[i].io.fd == s ) {
			//cwarn("found old = %d",i);
			iop_old = &self->dns.ios[i];
			break;
		}
		else
		if ( !iop_new && self->dns.ios[i].io.fd == -1 ) {
			//cwarn("found new = %d",i);
			iop_new = &self->dns.ios[i];
		}
	}
	if (!iop_old) {
		if (!iop_new) {
			cwarn("Can't find slot for io on fd %d",s);
			return;
		}
		else {
			iop = iop_new;
		}
	}
	else {
		iop = iop_old;
	}
	if (read || write) {
		if (iop->io.fd != s) {
			self->dns.ioc++;
		}
		ev_io_set( &iop->io, s, (read ? EV_READ : 0) | (write ? EV_WRITE : 0) );
		ev_io_start( self->loop, &iop->io );
	}
	else
	if ( iop->io.fd == s )
	{
		if (ev_is_active( &iop->io )) {
			ev_io_stop(self->loop, &iop->io);
		}
		ev_io_set( &iop->io, -1, 0);
		self->dns.ioc--;
	}
	if (self->dns.ioc <= 0) {
		ev_timer_stop(self->loop, &self->dns.tw);
	}
}

static void ns_io_cb (EV_P_ ev_io *w, int revents) {
	io_ptr * iop = (io_ptr *) w;
	dSELFby(w, dns.ios[ iop->id ]);
	
	ares_socket_t rfd = ARES_SOCKET_BAD, wfd = ARES_SOCKET_BAD;
	
	if (revents & EV_READ)  rfd = w->fd;
	if (revents & EV_WRITE) wfd = w->fd;
	
	ares_process_fd(self->dns.ares.channel, rfd, wfd);
	
	return;
}

static void ns_tw_cb (EV_P_ ev_timer *w, int revents) {
	dSELFby(w,dns.tw);
	fd_set readers, writers;
	FD_ZERO(&readers);
	FD_ZERO(&writers);
	
	ares_process(self->dns.ares.channel, &readers, &writers);
	
	return;
}



void ev_cnn_init(ev_cnn *self) {
	//memset(self,0,sizeof(ev_cnn));
	self->connect_timeout = 1.0;
	self->reconnect = 0.1;
	self->rw_timeout = 1.0;
	self->ipv4 = 2;
	self->ipv6 = 1;
	self->wnow = 1;
	
	self->dns.ares.options.sock_state_cb_data = self;
	self->dns.ares.options.sock_state_cb = (ares_sock_state_cb) ev_cnn_ns_state_cb;
	self->dns.ares.options.lookups = strdup("fb");
	self->dns.timeout.tv_sec  = self->connect_timeout;
	self->dns.timeout.tv_usec = (self->connect_timeout - (int)self->connect_timeout) * 1e6;
	
	int i;
	for (i=0;i<IOMAX;i++) {
		ev_init(&self->dns.ios[i].io,ns_io_cb);
		self->dns.ios[i].io.fd = -1;
		self->dns.ios[i].id = i;
	}
	ev_init(&self->dns.tw,ns_tw_cb);
	
	ares_init_options(&self->dns.ares.channel, &self->dns.ares.options, ARES_OPT_SOCK_STATE_CB | ARES_OPT_LOOKUPS );
}

void ev_cnn_clean(ev_cnn *self) {
	cnntrace(self, "destroying connection");
	do_disconnect(self);
	int i;
	io_ptr *iop;
	for (i=0; i<IOMAX; i++) {
		if ( self->dns.ios[i].io.fd > -1 ) {
			iop = &self->dns.ios[i];
			if (ev_is_active( &iop->io )) {
				ev_io_stop(self->loop, &iop->io);
			}
			
		}
	}
	
	if (self->rw.active) ev_io_stop(self->loop,&self->rw);
	if (self->ww.active) ev_io_stop(self->loop,&self->ww);
	if (self->tw.active) ev_timer_stop(self->loop,&self->tw);
	
	ares_destroy(self->dns.ares.channel);
	ares_destroy_options(&self->dns.ares.options);
	if (self->ai_top) freeaddrinfo(self->ai_top);
	if (self->wbuf) {
		int i;
		for ( i=0; i < self->wuse; i++) {
			if (self->wbuf[i].iov_base )
				free(self->wbuf[i].iov_base);
		}
		free(self->wbuf);
	}
}

static void ev_ares_ghbn_cb (ev_cnn * self, int status, int timeouts, struct hostent *hostent) {
	cwarn("callback ghbn");
	if(!hostent || status != ARES_SUCCESS) {
		cwarn("Failed to lookup %s: %s\n", self->host, ares_strerror(status));
		if (status == ARES_ECANCELLED) return;
		on_connect_failed(self,status);
		return;
	}
	int i,err;
	
	struct addrinfo ** curr = &self->ai_top;
	
	struct sockaddr_in * sin;
	struct sockaddr_in6 * sin6;
	
	char ip[INET6_ADDRSTRLEN];
	
	cwarn("Found address name %s\n", hostent->h_name);
	for (i = 0; hostent->h_addr_list[i]; ++i) {
		inet_ntop(hostent->h_addrtype, hostent->h_addr_list[i], ip, sizeof(ip));
		if (hostent->h_addrtype == AF_INET) {
			err = getaddrinfo(ip, 0, &hints4, curr);
			if (!err) {
				sin = (struct sockaddr_in *) (*curr)->ai_addr;
				sin->sin_port = htons(self->port);
				curr = &(*curr)->ai_next;
				self->dns.expire = time(NULL) + 60;
				cwarn("af_inet success: %s", ip);
			} else {
				cwarn("af_inet failed: %s",gai_strerror(err));
			}
		}
		else
		if (hostent->h_addrtype == AF_INET6) {
			err = getaddrinfo(ip, 0, &hints6, curr);
			if (!err) {
				sin6 = (struct sockaddr_in6 *) (*curr)->ai_addr;
				sin6->sin6_port = htons(self->port);
				curr = &(*curr)->ai_next;
				self->dns.expire = time(NULL) + 60;
				cwarn("af_inet6 success: %s", ip);
			} else {
				cwarn("af_inet6 failed: %s",gai_strerror(err));
			}
		}
		else {
			err = EAI_FAMILY;
		}
		
		if (err) {
			cwarn("gai: %s",gai_strerror(err));
		}
	}
	
	_do_connect(self);
}

static void ev_ares_aaaa_cb (ev_cnn * self, int status, int timeouts, unsigned char *abuf, int alen) {
	cwarn("callback aaaa %d",alen);
	
	struct ares_addr6ttl a[16];
	int count = 16;
	
	if(status != ARES_SUCCESS || ( status = ares_parse_aaaa_reply(abuf, alen, 0, a, &count) ) != ARES_SUCCESS) {
		cwarn("Failed to lookup AAAA %s: %s\n", self->host, ares_strerror(status));
		if (status == ARES_ECANCELLED) return;
		if (self->ipv4 && self->ipv4 < self->ipv6) {
			_resolve_a(self);
		} else {
			_resolve_ghbn(self);
			//on_connect_failed(self,EADDRNOTAVAIL);
		}
		return;
	}
	
	int minttl = 86400;
	struct addrinfo ** curr = &self->ai_top;
	struct sockaddr_in6 * sin6;
	char ip[INET6_ADDRSTRLEN];
		
	cwarn("ok %d", count);
	int i,err;
	for (i = 0; i < count; i++) {
		if (minttl > a[i].ttl)
			minttl = a[i].ttl;
		if (inet_ntop( AF_INET6, &a[i].ip6addr, ip, sizeof(ip) )) {
			err = getaddrinfo(ip, 0, &hints6, curr);
			if (!err) {
				sin6 = (struct sockaddr_in6 *) (*curr)->ai_addr;
				sin6->sin6_port = htons(self->port);
				curr = &(*curr)->ai_next;
			} else {
				cwarn("gai: %s",gai_strerror(err));
			}
		}
		else {
			cwarn("failed to convert address: %s",strerror(errno));
		}
	}
	
	self->dns.expire = time(NULL) + minttl;
	//cwarn("set expire to %ld + %d = %ld", time(NULL), minttl, self->dns.expire);
	
	_do_connect(self);
}

static void ev_ares_a_cb (ev_cnn * self, int status, int timeouts, unsigned char *abuf, int alen) {
	debug("callback a %d (%p:%s)",alen,self->host,self->host);
	struct ares_addrttl a[16];
	int count = 16;
	if(status != ARES_SUCCESS || ( status = ares_parse_a_reply(abuf, alen, 0, a, &count) ) != ARES_SUCCESS) {
		cwarn("Failed to lookup A %p:%s: %s\n", self->host,self->host, ares_strerror(status));
		if (status == ARES_ECANCELLED) return;
		if (self->ipv6 && self->ipv6 <= self->ipv4) {
			_resolve_aaaa(self);
		} else {
			_resolve_ghbn(self);
			//on_connect_failed(self,EADDRNOTAVAIL);
		}
		return;
	}
	int minttl = 86400;
	struct addrinfo **curr = &self->ai_top;
	char ip[INET_ADDRSTRLEN];
	struct sockaddr_in * sin;
		
	debug("ipv4 ok %d", count);
	int i,err;
	for (i = 0; i < count; i++) {
		if (minttl > a[self->addrc].ttl)
			minttl = a[self->addrc].ttl;
		if (inet_ntop( AF_INET, &a[i].ipaddr, ip, sizeof(ip) )) {
			err = getaddrinfo(ip, 0, &hints4, curr);
			if (!err) {
				sin = (struct sockaddr_in *) (*curr)->ai_addr;
				sin->sin_port = htons(self->port);
				curr = &(*curr)->ai_next;
			} else {
				cwarn("gai: %s",gai_strerror(err));
			}
		}
		else {
			cwarn("failed to convert address: %s",strerror(errno));
		}
	}
	self->dns.expire = time(NULL) + minttl;
	//cwarn("set expire to %ld + %d = %ld", time(NULL), minttl, self->dns.expire);
	
	_do_connect(self);
}

static inline void _resolve_ghbn(ev_cnn *self) {
	//ares_gethostbyname(self->dns.ares.channel, self->host, AF_INET, (ares_host_callback) ev_ares_ghbn_cb, self);
	ares_gethostbyname(self->dns.ares.channel, self->host, AF_UNSPEC, (ares_host_callback) ev_ares_ghbn_cb, self);
}

static inline void _resolve_aaaa(ev_cnn *self) {
	ares_search(self->dns.ares.channel, self->host, ns_c_in, ns_t_aaaa, (ares_callback) ev_ares_aaaa_cb, self);
}

static inline void _resolve_a(ev_cnn *self) {
	debug("_resolve_a %p:%s", self->host,self->host);
	ares_search(self->dns.ares.channel, self->host, ns_c_in, ns_t_a, (ares_callback) ev_ares_a_cb, self);
}

static void _do_resolve (ev_cnn *self) {
	if (unlikely( self->state != RESOLVING )) return;
	cnntrace(self, "_do_resolve: %s", self->host);
	if (!self->host) {
		on_connect_failed(self,EDESTADDRREQ);
		return;
	}
	if (getaddrinfo(self->host,0,&hints4,&self->ai_top) == 0) {
		struct sockaddr_in * sin = (struct sockaddr_in *) self->ai_top->ai_addr;
		sin->sin_port = htons(self->port);
		self->dns.expire = time(NULL) + 86400;
		_do_connect(self);
		return;
	}
	else
	if (getaddrinfo(self->host,0,&hints4,&self->ai_top) == 0) {
		struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *) self->ai_top->ai_addr;
		sin6->sin6_port = htons(self->port);
		self->dns.expire = time(NULL) + 86400;
		_do_connect(self);
		return;
	}
	
	
	if (self->ai_top) {
		freeaddrinfo( self->ai_top );
		self->ai_top = self->ai = 0;
	}
	if (self->ipv4 && self->ipv4 > self->ipv6) {
		_resolve_a(self);
	}
	else
	if (self->ipv6 && self->ipv6 > self->ipv4) {
		_resolve_aaaa(self);
	}
	else {
		on_connect_failed(self,EPFNOSUPPORT);
	}
}

static void on_reconnect_timer( struct ev_loop *loop, ev_timer *w, int revents ) {
	dSELFby(w,tw);
	ev_timer_stop( loop, w );
	cnntrace(self, "on_reconnect_timer");
	_do_connect(self);
}

static void on_connect_failed(ev_cnn * self, int err) {
	if (self->ww.fd > -1) close(self->ww.fd);
	if (self->rw.active) ev_io_stop(self->loop,&self->rw);
	if (self->ww.active) ev_io_stop(self->loop,&self->ww);
	if (self->tw.active) ev_timer_stop(self->loop,&self->tw);
	cnntrace(self, "on_connect_failed: %s. reconnect = %f", strerror(err), self->reconnect);
	if (self->reconnect > 0) {
		set_state(DISCONNECTING);
		if (self->on_connfail) {
			cnntrace(self, "CALL on_connfail");
			self->on_connfail(self,err);
			cnntrace(self, "DONE on_connfail");
		}
		if (self->state == DISCONNECTING) {
			set_state(RECONNECTING);
			ev_timer_init(&self->tw,on_reconnect_timer,self->reconnect,0.);
			ev_timer_start(self->loop,&self->tw);
		} else {
			cnntrace(self,"not doing do_reconnect after calling on_connfail");
		}
	}
	else {
		if (self->on_disconnect) {
			set_state(DISCONNECTING);
			cnntrace(self, "CALL on_disconnect");
			self->on_disconnect(self,err);
			cnntrace(self, "DONE on_disconnect");
			if (self->state == DISCONNECTING) {
				set_state(DISCONNECTED);
			} else {
				cnntrace(self,"not reset state after calling on_disconnect");
			}
		} else {
			set_state(DISCONNECTED);
		}
	}
}

void on_connect_reset(ev_cnn * self, int err) {
	if (self->ww.fd > -1) close(self->ww.fd);
	if (self->rw.active) ev_io_stop(self->loop,&self->rw);
	if (self->ww.active) ev_io_stop(self->loop,&self->ww);
	if (self->tw.active) ev_timer_stop(self->loop,&self->tw);
	cnntrace(self, "connection reset: %s (reconnect: %f)",strerror(err),self->reconnect);
	if (self->reconnect > 0) {
		set_state(DISCONNECTING);
		if (self->tw.active) {
			ev_timer_stop(self->loop,&self->tw);
		}
		if (self->on_disconnect) {
			cnntrace(self,"CALL on_disconnect");
			self->on_disconnect(self,err);
			cnntrace(self,"DONE on_disconnect");
		}
		if (self->state == DISCONNECTING) {
			// set_state(DISCONNECTED);
			_do_connect(self);
		} else {
			cnntrace(self,"not doing _do_connect after calling on_disconnect");
		}

		// set_state(RECONNECTING);
		// if (self->tw.active) {
		// 	ev_timer_stop(self->loop,&self->tw);
		// }
		// //ev_timer_init(&self->tw,on_reconnect_timer,self->reconnect,0.);
		// ev_timer_init(&self->tw,on_reconnect_timer,0.,0.); // after reset, try to reconnect immediately
		// ev_timer_start(self->loop,&self->tw);
		// if (self->on_disconnect)
		// 	self->on_disconnect(self,err);
	}
	else {
		if (self->on_disconnect) {
			set_state(DISCONNECTING);
			cnntrace(self, "CALL on_disconnect");
			self->on_disconnect(self,err);
			cnntrace(self, "DONE on_disconnect");
			if (self->state == DISCONNECTING) {
				set_state(DISCONNECTED);
			} else {
				cnntrace(self,"not reset state after calling on_disconnect");
			}
		} else {
			set_state(DISCONNECTED);
		}
	}

}

static void on_connect_timer ( struct ev_loop *loop, ev_timer *w, int revents ) {
	dSELFby(w,tw);
	cwarn("on con timer %p -> %p", w, self);
	ev_timer_stop( loop, w );
	ev_io_stop( loop, &self->ww );
	cnntrace(self,"on_connect_timer");
	on_connect_failed(self,ETIMEDOUT);
	return;
}

static void on_rw_timer(  struct ev_loop *loop, ev_timer *w, int revents ) {
	dSELFby(w,tw);
	cwarn("on rw timer %p -> %p", w, self);
	ev_timer_stop( loop, w );
	cnntrace(self,"on_rw_timer");
	on_connect_reset(self,ETIMEDOUT);
}

static void on_read_io( struct ev_loop *loop, ev_io *w, int revents ) {
	dSELFby(w,rw);
	ssize_t rc = 0;
	// debug("on rw io %p -> %p (fd: %d) (%d)", w, self, w->fd, revents);
	again:
	rc = read(w->fd,self->rbuf + self->ruse,self->rlen - self->ruse);
	//debug("read: %zu (%s)",rc,strerror(errno));
	if (rc > 0) {
		self->ruse += rc;
		if (self->on_read) {
			self->on_read(self,rc);
			if (self->ruse == self->rlen)
				on_connect_reset(self, ENOBUFS);//ENOSPC
		}
	}
	else if ( rc != 0 ) {
		switch(errno){
			case EINTR:
				goto again;
			case EAGAIN:
				return;
			default:
				//ev_io_stop(loop,w);
				cnntrace(self, "connection failed while read [io]: %s", strerror(errno));
				on_connect_reset(self,errno);
		}
	}
	else {
		cnntrace(self, "connection failed while read [io]: EOF: %s", strerror(errno));
		if (self->on_read)
			self->on_read(self,0);
		//on_read(self,0);
		ev_io_stop(loop,w);
		on_connect_reset(self,ECONNABORTED);
	}
}


static void on_connect_io( struct ev_loop *loop, ev_io *w, int revents ) {
	dSELFby(w,ww);
	//cwarn("on con io %p -> %p (fd: %d)", w, self, w->fd);
	
	struct sockaddr peer;
	socklen_t addrlen = sizeof(peer);
	
	again:
	if( getpeername( w->fd, &peer, &addrlen) == 0 ) {
		
		ev_timer_stop( loop, &self->tw );
		ev_io_stop( loop, w );
		
		ev_timer_init( &self->tw,on_rw_timer,self->rw_timeout,0 );
		
		ev_io_init( &self->rw, on_read_io, w->fd, EV_READ );
		ev_io_start( EV_DEFAULT, &self->rw );
		
		ev_io_init( &self->ww, on_write_io, w->fd, EV_WRITE );
		
		set_state(CONNECTED);
		
		if (self->on_connected) {
			cnntrace(self, "CALL on_connected");
			self->on_connected(self, &peer);
			cnntrace(self, "DONE on_connected");
		}
	} else {
		switch( errno ) {
			case EINTR:
				goto again;
			case EAGAIN:
				return;
			case ENOTCONN: {
				char x[1];
				recv( w->fd, x,1,0 ); // recv may give actual error
			}
			default:
				ev_timer_stop( loop, &self->tw );
				ev_io_stop( loop, w );
				cnntrace(self, "connection failed while getpeername [io]: %s", strerror(errno));
				on_connect_failed(self,errno);
				return;
		}
	}
}

// public interface
void do_connect(ev_cnn * self) {
	switch (self->state) {
		case INITIAL:
		case DISCONNECTING:
		case DISCONNECTED:
			// pass
			break;
		case RECONNECTING:
			warn("call to connect forced reconnection immediately");
			ev_timer_stop(self->loop,&self->tw);
			break;
		case RESOLVING:
		case CONNECTING:
		case CONNECTED:
			warn("call to connect is ignored since in state %s",strstate(self->state));
			return;
		default:
			warn("Unknown state %s:%d while do_connect", strstate(self->state),self->state);
			return;
	}
	cnntrace(self, "do_connect");
	_do_connect(self);
}


static void _do_connect(ev_cnn * self) {
	int sock;
	time_t now = time(NULL);
	self->now = now;

	//cwarn("connecting to %s with timeout %f (addrc=%d, exp in %ld - %ld = %ld)",self->host, self->connect_timeout, self->addrc, self->now, self->dns.expire, self->now - self->dns.expire);
	if (!self->ai_top || self->now > self->dns.expire) {
		set_state(RESOLVING);
		_do_resolve(self);
		return;
	}
	set_state(CONNECTING);

	if (!self->ai || !(self->ai = self->ai->ai_next)) {
		self->ai = self->ai_top;
	}
	struct addrinfo *ai = self->ai;
	
	if (self->connect_timeout > 0) {
		cnntrace(self, "start connect timeout %0.4fs",self->connect_timeout);
		ev_timer_init( &self->tw, on_connect_timer, self->connect_timeout, 0. );
		ev_timer_start( self->loop, &self->tw );
	}
	
	//cwarn("create socket of family %d",ai->ai_family);
	
	do {
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	} while (sock < 0 && errno == EINTR);
	
	if (sock < 0) {
		cnntrace(self, "socket creation failed: %s", strerror(errno));
		on_connect_failed(self, errno);
		return;
	}
	
	
	fcntl(sock, F_SETFL, O_NONBLOCK | O_RDWR);
	struct linger linger = { 0 };
	linger.l_onoff = 1;
	linger.l_linger = 0;
	if( setsockopt(sock, SOL_SOCKET, SO_LINGER,(const char *) &linger,sizeof(linger)) == -1) {
		cnntrace(self, "set linger failed: %s", strerror(errno));
	}
	
	again:
	
	if (
		connect( sock, ai->ai_addr, ai->ai_addrlen) == 0
	) {
		on_connect_io(EV_DEFAULT, &self->ww, 0);
		return;
	} else {
		//warn("connect: %s...",strerror(errno));
		switch (errno) {
			case EINPROGRESS:
			case EALREADY:
			case EWOULDBLOCK:
				// async connect now in progress
				//client->state = CLIENT_CONNECTING;
				
				break;
			case EINTR:
				goto again;
			default: {
				cnntrace(self, "connect() failed: %s", strerror(errno));
				return on_connect_failed( self, errno );
			}
		}
	}
	cnntrace(self, "start io ww");
	ev_io_init( &self->ww, on_connect_io, sock, EV_WRITE );
	ev_io_start( EV_DEFAULT, &self->ww );
}

void do_disconnect(ev_cnn * self) {
	cnntrace(self, "do_disconnect");
	// only from state CONNECTED event on_disconnect emitted
	if (self->state == CONNECTED) {
		ev_timer_stop(self->loop,&self->tw);
		ev_io_stop(self->loop,&self->ww);
		ev_io_stop(self->loop,&self->rw);
		if (self->ww.fd > -1) close(self->ww.fd);
		if (self->on_disconnect) {
			set_state(DISCONNECTING);
			cnntrace(self, "CALL on_disconnect");
			self->on_disconnect(self,0);
			cnntrace(self, "DONE on_disconnect");
			if (self->state == DISCONNECTING) {
				set_state(DISCONNECTED);
			} else {
				cnntrace(self,"not reset state after calling on_disconnect");
				return;
			}
		}		
	} else {
		switch (self->state) {
			case INITIAL:
				return;
			case RECONNECTING:
				ev_timer_stop(self->loop,&self->tw);
				break;
			case RESOLVING:
				ares_cancel(self->dns.ares.channel);
				break;
			case CONNECTING:
				ev_timer_stop(self->loop,&self->tw);
				ev_io_stop(self->loop,&self->ww);
				if (self->ww.fd > -1) close(self->ww.fd);
				break;
			case DISCONNECTING:
			case DISCONNECTED:
				break;
			default:
				warn("Unknown state %s:%d during disconnect", strstate(self->state), self->state);
				break;
		}
	}
	set_state(DISCONNECTED);
	return;
}

static void on_write_io( struct ev_loop *loop, ev_io *w, int revents ) {
	dSELFby(w,ww);
	
	ssize_t wr;
	int iovcur;
	struct iovec *iov;
	
	//cwarn("on ww io %p -> %p (fd: %d) [ wbufs: %d of %d ]", w, self, w->fd, self->wuse, self->wlen);
	
	ev_timer_stop( self->loop, &self->tw );
	
	again:
	wr = writev(w->fd,self->wbuf,self->wuse);
	if (wr > -1) {
		//cwarn("written: %zu",wr);
		for (iovcur = 0; iovcur < self->wuse; iovcur++) {
			iov = &(self->wbuf[iovcur]);
			if (wr < iov->iov_len) {
				//cwarn("Written %d of iov size %d",wr,iov->iov_len);
				memmove( iov->iov_base, iov->iov_base + wr, iov->iov_len - wr );
				iov->iov_len -= wr;
				//iovcur--;
				break;
			} else {
				free(iov->iov_base);
				wr -= iov->iov_len;
			}
		}
		self->wuse -= iovcur;
		//cwarn("freed %d iovs, left %d",iovcur, self->wuse);
		if (self->wuse == 0) {
			ev_io_stop(loop,w);
		} else {
			memmove( self->wbuf, self->wbuf + iovcur, self->wuse * sizeof(struct iovec) );
			
			ev_timer_again( self->loop,&self->tw ); //written not all, so restart timer
			return;
		}
	}
	else {
		switch(errno){
			case EINTR:
				goto again;
			case EAGAIN:
				ev_timer_again( self->loop,&self->tw );
				return;
			default:
				cnntrace(self, "connection failed while write [io]: %s", strerror(errno));
				on_connect_reset(self,errno);
				return;
		}
	}
}


void do_write(ev_cnn *self, char *buf, size_t len) {
	if ( len == 0 ) len = strlen(buf);
	//cwarn("do_write");
	if (self->wuse) {
		//cwarn("have wbuf, use it");
		if (self->wuse == self->wlen) {
			self->wlen += 2;
			self->wbuf = realloc(self->wbuf, sizeof(struct iovec) * ( self->wlen ));
		}
		self->wbuf[self->wuse].iov_base = memdup(buf,len);
		self->wbuf[self->wuse].iov_len  = len;
		//cwarn("iov[%d] stored %zu: %p",self->wuse,len, self->wbuf[self->wuse].iov_base);
		self->wuse++;
		return;
	}
	
	ssize_t wr = 0;
	
	if (self->wnow) {
		again:
		
		wr = write( self->ww.fd, buf, len );
		//cwarn("writing %d",len);
		if ( wr == len ) {
			// success
			//cwarn("written now %zu %u",wr, *((uint32_t *)(buf + 8)) );
			return;
		}
		else
		if (wr > -1) {
			//cwarn("written part %zu %u",wr, *((uint32_t *)(buf + 8)) );
			//partial write, passthru
		}
		else
		{
			switch(errno) {
				case EINTR:
					goto again;
				case EAGAIN:
					wr = 0;
					break;
				default:
					cnntrace(self, "connection failed while write [now]: %s", strerror(errno));
					on_connect_reset(self,errno);
					return;
			}
		}
	}
	
	self->wlen = 2;
	self->wbuf = calloc( self->wlen, sizeof(struct iovec) );
	self->wbuf[0].iov_base = memdup(buf + wr,len - wr);
	self->wbuf[0].iov_len  = len - wr;
	self->wuse = 1;
	
	ev_timer_again(self->loop,&self->tw);
	ev_io_start(self->loop,&self->ww);
	
	return;
}
