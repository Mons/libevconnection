/*
usage:
	BOOT:
		I_EV_CNN_API(PackageName);

	void new (...)
		PPCODE:
			xs_ev_cnn_new(YourType); // declares YourType * self, set ST(0)
			self->yourprops = ...
			self->cnn.on_read = (c_cb_read_t) your_read_handler;
			...
			XSRETURN(1);
	void method( ... )
		PPCODE:
			xs_ev_cnn_self(YourType); // declares YourType * self
			SV *cb = ST(items - 1); // suppose callback is last arg

			xs_ev_cnn_checkconn(self,cb);
*/

#include "evconnection.h"
#include "libevconnection.c"

#define NEED_newRV_noinc
#include "ppport.h"

#define dObjBy(Type,obj,ptr,xx) Type * obj = (Type *) ( (char *) ptr - (ptrdiff_t) &((Type *) 0)-> xx )

#define xs_ev_cnn_struct\
	ev_cnn cnn;\
	SV *self;\
	HV *stash;\
	\
	SV *host;\
	\
	SV *rbuf;\
	\
	SV *connected;\
	SV *disconnected;\
	SV *connfail;\
	\
	ev_timer postpone_timer;\
	AV *postpone;

typedef struct {
	xs_ev_cnn_struct;
#if XSEV_CON_HOOKS
	void (*on_disconnect_before)(void *, int);
	void (*on_disconnect_after)(void *, int);
	void (*on_connect_before)(void *, struct sockaddr *);
	void (*on_connect_after)(void *, struct sockaddr *);
#endif
} xs_ev_cnn;

#define I_EV_CNN_API(Module) STMT_START {\
	char * file = __FILE__;\
	newXS(Module "::connect", XS_ev_cnn_connect, file);\
	newXS(Module "::disconnect", XS_ev_cnn_disconnect, file);\
	newXS(Module "::reconnect", XS_ev_cnn_reconnect, file);\
	newXS(Module "::server", XS_ev_cnn_server, file);\
	newXS(Module "::host", XS_ev_cnn_host, file);\
	newXS(Module "::port", XS_ev_cnn_port, file);\
} STMT_END


#define xs_ev_cnn_new(Type)\
	if (items < 2 || !SvROK(ST(1)) || SvTYPE(SvRV(ST(1))) != SVt_PVHV) croak("Usage: %s->new({ options })",SvPV_nolen(ST(0)));\
	Type * self = (Type *) safemalloc( sizeof(Type) ); \
	memset(self,0,sizeof(Type)); \
	self->stash = gv_stashpv(SvPV_nolen(ST(0)), TRUE); \
	{\
		SV *iv = newSViv(PTR2IV( self ));\
		ST(0) = sv_2mortal(sv_bless(newRV_noinc (iv), self->stash));\
		self->self = SvRV( ST(0) ); \
	} \
	self->cnn.loop = EV_DEFAULT; \
	ev_cnn_init(&self->cnn);\
	HV *args = (HV*) SvRV(ST(1));\
	ev_cnn *cnn = &self->cnn;\
	{\
		int read_buffer = 0x20000;\
		SV **key;\
		if ((key = hv_fetchs(args, "read_buffer", 0)) ) read_buffer = SvNV(*key); \
		if ((key = hv_fetchs(args, "timeout", 0)) ) cnn->connect_timeout = cnn->rw_timeout = SvNV(*key); \
		if ((key = hv_fetchs(args, "read_buffer", 0)) && SvOK(*key) && SvUV(*key) > 0 ) read_buffer = SvUV(*key); \
		if ((key = hv_fetchs(conf, "reconnect", 0)) ) { \
			cnn->reconnect = SvNV(*key); \
		} \
		else { \
			cnn->reconnect = 1./3; \
		} \
		\
		self->rbuf = newSV( read_buffer ); \
		SvUPGRADE( self->rbuf, SVt_PV ); \
		cnn->rbuf = SvPVX(self->rbuf); \
		cnn->rlen = SvLEN(self->rbuf); \
		\
		if ((key = hv_fetchs(conf, "connected", 0)) && SvROK(*key)) SvREFCNT_inc(self->connected = *key);\
		if ((key = hv_fetchs(conf, "disconnected", 0)) && SvROK(*key)) SvREFCNT_inc(self->disconnected = *key);\
		if ((key = hv_fetchs(conf, "connfail", 0)) && SvROK(*key)) SvREFCNT_inc(self->connfail = *key);\
		\
		cnn->on_connected = (c_cb_conn_t) xs_ev_cnn_on_connected_cb;\
		cnn->on_disconnect = (c_cb_discon_t) xs_ev_cnn_on_disconnect_cb;\
		cnn->on_connfail = (c_cb_err_t) xs_ev_cnn_on_connfail_cb;\
		\
		if ((key = hv_fetch(conf, "host", 4, 0)) && SvOK(*key)) {\
			SvREFCNT_inc(self->host = *key); \
			self->cnn.host = SvPV_nolen(*key);\
		}\
		else { croak("host required"); } \
		if ((key = hv_fetch(conf, "port", 4, 0)) && SvOK(*key)) { \
			self->cnn.port = SvUV( *key ); \
		} \
		else { croak("port required"); } \
		\
		self->postpone = 0;\
		ev_timer_init(&self->postpone_timer,xs_ev_cnn_postpone_cb,0,0);\
		\
	} \

#define xs_ev_cnn_self(Type) register Type *self = ( Type * ) SvUV( SvRV( ST(0) ) )

#define xs_ev_cnn_destroy(self)\
	if (!PL_dirty && self->postpone) {\
		xs_ev_cnn_postpone_cb ( self->cnn.loop, &self->postpone_timer, 0);\
	}\
	\
	ev_cnn_clean(&self->cnn);\
	\
	if (self->connected)    { SvREFCNT_dec(self->connected);    self->connected    = 0; } \
	if (self->connfail)     { SvREFCNT_dec(self->connfail);     self->connfail     = 0; } \
	if (self->disconnected) { SvREFCNT_dec(self->disconnected); self->disconnected = 0; }\
	\
	if (PL_dirty) return; \
	if (self->host) SvREFCNT_dec(self->host); \
	if (self->rbuf) SvREFCNT_dec(self->rbuf); \
	safefree(self);

#define xs_ev_cnn_checkconn(_self,_cb) STMT_START{ \
		if (unlikely(!_self->self || !SvOK(_self->self))) return ;\
		if (unlikely(_self->cnn.state != CONNECTED)) { \
			if (!_self->postpone) _self->postpone = newAV(); \
			AV *pp = newAV(); \
			av_push(_self->postpone,newRV_noinc((SV *)pp)); \
			SvREFCNT_inc(cb); \
			av_push(pp,cb); \
			av_push(pp,&PL_sv_undef); \
			av_push(pp,newSVpv( "Not connected",0 )); \
			ev_timer_start(_self->cnn.loop, &_self->postpone_timer); \
			XSRETURN_UNDEF; \
			return; \
		} \
} STMT_END

XS(XS_ev_cnn_connect);
XS(XS_ev_cnn_connect)
{
	dVAR;dXSARGS;
	if (items != 1) croak_xs_usage(cv,  "self");
	PERL_UNUSED_VAR(ax);
	SP -= items;

	xs_ev_cnn_self(xs_ev_cnn);
	do_connect(&self->cnn);

	XSRETURN_UNDEF;
	PUTBACK;
	return;
}

XS(XS_ev_cnn_disconnect);
XS(XS_ev_cnn_disconnect)
{
	dVAR;dXSARGS;
	if (items != 1) croak_xs_usage(cv,  "self");
	PERL_UNUSED_VAR(ax);
	SP -= items;

	xs_ev_cnn_self(xs_ev_cnn);
	do_disconnect(&self->cnn);

	XSRETURN_UNDEF;
	PUTBACK;
	return;
}

XS(XS_ev_cnn_reconnect);
XS(XS_ev_cnn_reconnect)
{
	dVAR;dXSARGS;
	if (items != 1) croak_xs_usage(cv,  "self");
	PERL_UNUSED_VAR(ax);
	SP -= items;

	xs_ev_cnn_self(xs_ev_cnn);
	do_disconnect(&self->cnn);
	do_connect(&self->cnn);

	XSRETURN_UNDEF;
	PUTBACK;
	return;
}

XS(XS_ev_cnn_server);
XS(XS_ev_cnn_server)
{
	dVAR;dXSARGS;
	if (items != 1) croak_xs_usage(cv,  "self");
	PERL_UNUSED_VAR(ax);
	SP -= items;

	xs_ev_cnn_self(xs_ev_cnn);
	ST(0) = sv_2mortal(newSVpvf("%s:%hu",self->cnn.host,self->cnn.port));

	XSRETURN(1);
	PUTBACK;
	return;
}

XS(XS_ev_cnn_host);
XS(XS_ev_cnn_host)
{
	dVAR;dXSARGS;
	if (items != 1) croak_xs_usage(cv,  "self");
	PERL_UNUSED_VAR(ax);
	SP -= items;

	xs_ev_cnn_self(xs_ev_cnn);
	ST(0) = sv_2mortal(newSVpvf("%s",self->cnn.host));

	XSRETURN(1);
	PUTBACK;
	return;
}

XS(XS_ev_cnn_port);
XS(XS_ev_cnn_port)
{
	dVAR;dXSARGS;
	if (items != 1) croak_xs_usage(cv,  "self");
	PERL_UNUSED_VAR(ax);
	SP -= items;

	xs_ev_cnn_self(xs_ev_cnn);
	ST(0) = sv_2mortal(newSVuv( (UV)(self->cnn.port) ));

	XSRETURN(1);
	PUTBACK;
	return;
}


#define xs_ev_cnn_on_connect(self, before, after) STMT_START {\
	if (before) self->on_connect_before = before;\
	if (after) self->on_connect_after = after;\
} STMT_END

#define xs_ev_cnn_on_disconnect(self, before, after) STMT_START {\
	if (before) self->on_disconnect_before = before;\
	if (after) self->on_disconnect_after = after;\
} STMT_END


void xs_ev_cnn_on_disconnect_cb(ev_cnn *cnn, int error, const char *reason) {
	xs_ev_cnn * self = (xs_ev_cnn *) cnn;
	dSP;
#if XSEV_CON_HOOKS
	if (self->on_disconnect_before)
		self->on_disconnect_before( (void *) self, error );
#endif
	if (self->disconnected) {
		ENTER;
		SAVETMPS;
		PUSHMARK(SP);
		EXTEND(SP, 2);
			PUSHs( sv_2mortal( newRV_inc(self->self) ) );
			if (error != 0 && reason != NULL) {
				PUSHs( sv_2mortal( newSVpvf( "%s: %s", strerror(error), reason ) ) );
			} else if (reason != NULL) {
				PUSHs( sv_2mortal( newSVpv( reason,0 ) ) );
			} else {
				PUSHs( sv_2mortal( newSVpv( strerror(error),0 ) ) );
			}
		PUTBACK;
		errno = error;
		call_sv( self->disconnected, G_DISCARD | G_VOID );
		FREETMPS;
		LEAVE;
	}
#if XSEV_CON_HOOKS
	if (self->on_disconnect_after)
		self->on_disconnect_after( (void *) self, error );
#endif
}

void xs_ev_cnn_on_connected_cb(ev_cnn *cnn, struct sockaddr *peer) {
	xs_ev_cnn * self = (xs_ev_cnn *) cnn;
	dSP;

#if XSEV_CON_HOOKS
	if (self->on_connect_before)
		self->on_connect_before( (void *) self, peer );
#endif

	if (self->connected && SvOK(self->connected)) {
		char ip[INET6_ADDRSTRLEN];
		unsigned short port = 0;
		switch (peer->sa_family) {
			case AF_INET: {
				struct sockaddr_in * sin = (struct sockaddr_in *) peer;
				inet_ntop(peer->sa_family, &sin->sin_addr, ip, sizeof(ip));
				port = ntohs( sin->sin_port );
				break;
			}
			case AF_INET6: {
				struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *) peer;
				inet_ntop(peer->sa_family,&sin6->sin6_addr,ip,sizeof(ip) );
				port = ntohs( sin6->sin6_port );
				break;
			}
			default:
				ip[0] = 0;
				warn("Bad sa family: %d", peer->sa_family);
		}

		ENTER;
		SAVETMPS;
		PUSHMARK(SP);
		EXTEND(SP, 3);
			PUSHs( sv_2mortal( newRV_inc(self->self) ) );
			PUSHs( sv_2mortal( newSVpv( ip,0 ) ) );
			PUSHs( sv_2mortal( newSVuv( port ) ) );
		PUTBACK;
		call_sv( self->connected, G_DISCARD | G_VOID );
		FREETMPS;
		LEAVE;
	}

#if XSEV_CON_HOOKS
	if (self->on_connect_after)
		self->on_connect_after( (void *) self, peer );
#endif
}

void xs_ev_cnn_on_connfail_cb(ev_cnn *cnn, int err) {
	xs_ev_cnn * self = (xs_ev_cnn *) cnn;
	dSP;
	if (self->connfail) {
		ENTER;
		SAVETMPS;
		PUSHMARK(SP);
		EXTEND(SP, 2);
			PUSHs( sv_2mortal( newRV_inc(self->self) ) );
			PUSHs( sv_2mortal( newSVpvf( "%s",strerror(err) ) ) );
		PUTBACK;
		errno = err;
		call_sv( self->connfail, G_DISCARD | G_VOID );
		FREETMPS;
		LEAVE;
	}
}

void xs_ev_cnn_postpone_cb ( struct ev_loop *loop,  ev_timer *w, int revents) {
	dObjBy(xs_ev_cnn, self, w, postpone_timer);
	ev_timer_stop( loop, w );
	dSP;

	ENTER;
	SAVETMPS;
	SV **sp1 = PL_stack_sp;

	AV *postpone = (AV *) sv_2mortal((SV *)self->postpone);

	self->postpone = 0;

	while (av_len( postpone ) > -1) {
		AV *pp = (AV *) SvRV(sv_2mortal(av_shift( postpone )));
		SV *cb = sv_2mortal(av_shift(pp));
		ENTER;
		SAVETMPS;
		PUSHMARK(SP);
		EXTEND(SP, av_len(pp)+1);
		while (av_len(pp) > -1) {
			XPUSHs( sv_2mortal(av_shift(pp)) );
		}
		PUTBACK;
		call_sv( cb, G_DISCARD | G_VOID );
		FREETMPS;
		LEAVE;
	}

	PL_stack_sp = sp1;

	FREETMPS;
	LEAVE;
}

