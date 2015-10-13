#include "evconnection.h" // also provide ev.h + ares.h

#include <stdlib.h>
#include <stdio.h>
#include <sys/un.h>

static void on_connected ( ev_cnn * cnn, struct sockaddr *peer ) {
	char ip[1024];
	switch ( peer->sa_family ) {
		case AF_INET:
			inet_ntop( AF_INET, &((struct sockaddr_in *) peer)->sin_addr, ip, sizeof(ip));
			cwarn("connected address: %s:%d", ip, ntohs( ((struct sockaddr_in *) peer)->sin_port ) );
			break;
		case AF_INET6:
			inet_ntop( AF_INET6, &((struct sockaddr_in6 *) peer)->sin6_addr, ip, sizeof(ip));
			cwarn("connected address: %s:%d", ip, ntohs( ((struct sockaddr_in6 *) peer)->sin6_port ) );
			break;
		case AF_UNIX:
			cwarn("connected address: unix:%s", ((struct sockaddr_un *) peer)->sun_path );
			break;
		default:
			cwarn("Uknown family: %d",peer->sa_family);
	}
	
	//char *buf = "GET / HTTP/1.0\r\n\r\n";
	
	do_write(cnn, "GET /",0);
	do_write(cnn, " HTTP/1.0\r\n",0);
	do_write(cnn, "\r\n",0);
}

static void on_read ( ev_cnn * cnn, ssize_t len ) {
	cwarn("read %zu",len);
	cwarn("%-.*s", (int)cnn->ruse, cnn->rbuf);
	//cnn->ruse = 10;
}

int main (int argc, char *argv[]) {
	struct ev_loop *loop = EV_DEFAULT;
	
	if (argc < 3) { fprintf(stderr, "Usage:\n\t%s host port\n",argv[0]); return 1; }
	
	char *host = argv[1];
	char *port = argv[2];
	int iport = atoi(port);
	int status;
	if ((status = ares_library_init(ARES_LIB_INIT_ALL) )!= ARES_SUCCESS) {
		fprintf(stderr,"Ares error: %s\n",ares_strerror(status));
		return 1;
	}
	ev_cnn cnn;
	struct iovec iov[2];
	char rbuf[256];
	memset(&cnn,0,sizeof(cnn));
	ev_cnn_init(&cnn);
	// cnn.trace = 0;
	cnn.loop = loop;
	
	cnn.host = host;
	cnn.port = iport;
	// for write
	cnn.iov = iov;
	cnn.iovcnt = 2;
	//for read
	cnn.rbuf = rbuf;
	cnn.rlen = sizeof(rbuf);
	cnn.reconnect = 0;
	
	cnn.on_connected = (c_cb_conn_t) on_connected;
	cnn.on_read = (c_cb_read_t) on_read;
	
	cwarn("connect to %s:%d", host,iport);
	
	do_connect(&cnn);
	
	// Run loop
	ev_run (loop, 0);
	ev_cnn_clean(&cnn);
	ares_library_cleanup();
}
