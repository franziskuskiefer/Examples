/**
 * SSL SRP Client
 *
 * author franziskus
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// This is a context that we pass to all client callbacks
typedef struct srp_arg_st {
	char *srppassin;
	char *srplogin;
	int msg; /* copy from c_msg */
	int debug; /* copy from c_debug */
	int amp; /* allow more groups */
	int strength /* minimal size for N */;
} SRP_CLIENT_ARG;

// for srp callbacks
SRP_CLIENT_ARG srp_client_arg = {"password","user",0,0,0,1024};

int startSocketConnection(const char *hostname, int port) {
	int sd;
    struct hostent *host;
    struct sockaddr_in addr;

	if ((host = gethostbyname(hostname)) == NULL) {
		perror(hostname);
		abort();
	}

	sd = socket(PF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
	addr.sin_addr.s_addr = *((in_addr_t *) host->h_addr);
	bzero (&(addr.sin_zero), 8);

	if (connect(sd, (struct sockaddr*) &addr, sizeof(struct sockaddr)) != 0) {
		close(sd);
		perror(hostname);
		abort();
	}

    return sd;
}

static char *ssl_give_srp_client_pwd_cb(SSL *s, void *arg) {
	return BUF_strdup((char *)((SRP_CLIENT_ARG *)arg)->srppassin);
}

SSL_CTX* InitClientCTX(void) {
	SSL_CTX *ctx;

	// Init OpenSSL
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_library_init();

    // create new SSL context
    const SSL_METHOD *method = TLSv1_client_method();
    ctx = SSL_CTX_new(method);
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		abort();
	}

	// Bug workarounds // XXX: necessary?
	SSL_CTX_set_options(ctx,SSL_OP_ALL);

	// SRP // XXX: necessary?
	SSL_CTX_SRP_CTX_init(ctx);

	// set cipher list -> only want SRP without certs here
	if (SSL_CTX_set_cipher_list(ctx, "aNULL:!eNULL:!LOW:!EXPORT:@STRENGTH:!ADH:!AECDH") != 1){
		printf("SSL_CTX_set_cipher_list failed");
	}

    // set SRP susername
    if (!SSL_CTX_set_srp_username(ctx, srp_client_arg.srplogin)){
    	printf("SSL_CTX_set_srp_username failed");
    	ERR_print_errors_fp(stderr);
    }

    // hand over srp_client_arg to context
    // give callbacks to context
    SSL_CTX_set_srp_cb_arg(ctx,&srp_client_arg);
    SSL_CTX_set_srp_client_pwd_callback(ctx, ssl_give_srp_client_pwd_cb);
    SSL_CTX_set_srp_strength(ctx, srp_client_arg.strength);

	return ctx;
}

int main(int argc, char **argv) {
	if (argc < 4) {
		printf("Usage: ./server <server> <port> <Message>\n");
		return 1;
	}

	SSL_CTX *ctx;
	int server;
	SSL *ssl;
	char buf[1024];
    int bytes;

    // create client context
    ctx = InitClientCTX();

    // start socket connection to server
    server = startSocketConnection(argv[1], atoi(argv[2]));
    printf("Connected to %s:%s\n", argv[1],argv[2]);

    // create new SSL from context
    ssl = SSL_new(ctx);

    // bind SSL to server socket connection
    SSL_set_fd(ssl, server);

    // connect to SSL server -> do handshake stuff
    int error = SSL_get_error(ssl, SSL_connect(ssl));

    if (error != SSL_ERROR_NONE) {
    	ERR_print_errors_fp (stderr);
    	printf("Error opening SSL connection: %d\n", error);
    } else { // if handshake was successful we have a SSL connection now
    	printf("Successfully connected to Server via SSL\n");
		char *msg = argv[3];

		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));

		// do a dummy communication
		SSL_write(ssl, msg, strlen(msg));
		bytes = SSL_read(ssl, buf, sizeof(buf));
		buf[bytes] = 0;
		printf("Received: \"%s\"\n", buf);

		SSL_free(ssl);
	}
    close(server);
    SSL_CTX_free(ctx);

    return 0;
}
