//SSL-Server.c
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL    -1

/* SRP server */
/* This is a context that we pass to SRP server callbacks */
typedef struct srp_server_arg_st {
	char *expected_user;
	char *pass;
} SRP_SERVER_ARG;

int OpenListener(int port) {
	int sd;
	struct sockaddr_in addr;

	sd = socket(PF_INET, SOCK_STREAM, 0);
//	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	bzero (&(addr.sin_zero), 8);
	if (bind(sd, (struct sockaddr*)&addr, sizeof(struct sockaddr)) != 0){
		perror("Can't bind port");
		abort();
	}
	if (listen(sd, 10) != 0) {
		perror("Can't configure listening port");
		abort();
	}
	return sd;
}

static int ssl_srp_server_param_cb(SSL *s, int *ad, void *arg) {
	SRP_SERVER_ARG * p = (SRP_SERVER_ARG *) arg;
//	int i;
//	printf("arg@: %p\n", arg);
//	for(i = 0; i < 30; ++i){
//		printf("%d: %lu\n", i, (unsigned long)*((char*)((SRP_SERVER_ARG*)arg)+i*sizeof(char)));
//	}
//	printf("user[0]: %c\n", *(char*)((SRP_SERVER_ARG*)arg));
//	printf("user[1]: %c\n", *((char*)((SRP_SERVER_ARG*)arg)+sizeof(char)));
//	printf("user[2]: %c\n", *((char*)((SRP_SERVER_ARG*)arg)+2*sizeof(char)));

//	printf("SSL_get_srp_username(s): %s", SSL_get_srp_username(s));
////	printf("p->expected_user: %s", p->expected_user);

	// FIXME: arg is empty...somehow the server does not know any user or password...
//	if (strcmp(p->expected_user, SSL_get_srp_username(s)) != 0) {
//		fprintf(stderr, "User %s doesn't exist\n", SSL_get_srp_username(s));
//		return SSL3_AL_FATAL;
//	}
//	if (SSL_set_srp_server_param_pw(s, p->expected_user, p->pass, "1024") < 0) {
//		*ad = SSL_AD_INTERNAL_ERROR;
//		return SSL3_AL_FATAL;
//	}

	SSL_set_srp_server_param_pw(s, SSL_get_srp_username(s), "pwd", "1024");

	return SSL_ERROR_NONE;
}

// FIXME: dummy function
static int verify_callback(int ok, X509_STORE_CTX *ctx) {
	printf("ok: %d", ok);
	return ok;
}

SSL_CTX* InitServerCTX(void) {
	SSL_CTX *ctx;
	// for srp callbacks
	SRP_SERVER_ARG srp_server_arg = {"user","pwd"};

	OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
	SSL_load_error_strings();   /* load all error messages */
	SSL_library_init();
	const SSL_METHOD *method = TLSv1_server_method();  /* create new server-method instance */
	ctx = SSL_CTX_new(method);   /* create new context from method */

	// set

	// need also SRP
	SSL_CTX_SRP_CTX_init(ctx);
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		abort();
	}
	// set cipher list
	if (SSL_CTX_set_cipher_list(ctx, "aNULL:!eNULL:!LOW:!EXPORT:@STRENGTH:!ADH:!AECDH") != 1) {
		// aNULL:!eNULL:!LOW:!EXPORT:@STRENGTH
		printf("SSL_CTX_set_cipher_list failed\n");
	}

	SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,verify_callback);
	SSL_CTX_set_srp_cb_arg(ctx, &srp_server_arg);
	SSL_CTX_set_srp_username_callback(ctx, ssl_srp_server_param_cb);

	return ctx;
}

void Servlet(SSL* ssl){ /* Serve the connection -- threadable */
	char buf[1024];
	char reply[1024];
	int sd, bytes;
	const char* HTMLecho="<html><body><pre>%s</pre></body></html>\n\n";

//	// check the clients password and username
//	if (SSL_set_srp_server_param_pw(ssl, "user", "password", "1024") != 1) {
//		printf("SSL_set_srp_server_param_pw failed\n");
//		ERR_print_errors_fp(stderr);
//	}

	int error = SSL_get_error(ssl, SSL_accept(ssl));

	if (error != SSL_ERROR_NONE) {    /* do SSL-protocol accept SSL_accept(ssl) != 1*/
		ERR_print_errors_fp (stderr);
		printf("Error accepting SSL connection: %d\n", error);
	} else {
		bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
		if ( bytes > 0 ) {
			buf[bytes] = 0;
			printf("Client msg: \"%s\"\n", buf);
			sprintf(reply, HTMLecho, buf);   /* construct reply */
			SSL_write(ssl, reply, strlen(reply)); /* send reply */
		} else
			ERR_print_errors_fp(stderr);
	}
	sd = SSL_get_fd(ssl);       /* get socket connection */
	SSL_free(ssl);         /* release SSL state */
	close(sd);          /* close connection */
}

int main(int argc, char **argv) {
	SSL_library_init();

	if (argc < 2) {
		printf("Usage: ./server <port>\n");
		return 1;
	}

	SSL_CTX *ctx;
	int server;

	ctx = InitServerCTX();        /* initialize SSL */
	server = OpenListener(atoi(argv[1]));    /* create server socket */
//	while (1) {
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	SSL *ssl;

	int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
	ssl = SSL_new(ctx);              /* get new SSL state with context */
	printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
//	STACK_OF(SSL_CIPHER) *ciphers = SSL_get_ciphers(ssl);
//	while (sk_SSL_CIPHER_num(ciphers) > 0) {
//		printf("%s\n",SSL_CIPHER_get_name(sk_SSL_CIPHER_pop(ciphers)));
//	}
	printf("got ssl from ctx\n");
	SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
	printf("set socket connection for this ssl\n");
	Servlet(ssl);         /* service connection */
//	}
	close(server);          /* close server socket */
	SSL_CTX_free(ctx);         /* release context */
}
