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

// for srp callbacks
SRP_SERVER_ARG srp_server_arg = {"user","password"};

int startServerListener(int port) {
	int sd;
	struct sockaddr_in addr;

	sd = socket(PF_INET, SOCK_STREAM, 0);
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
	if (strcmp(p->expected_user, SSL_get_srp_username(s)) != 0) {
		fprintf(stderr, "User %s doesn't exist\n", SSL_get_srp_username(s));
		return SSL3_AL_FATAL;
	}
	if (SSL_set_srp_server_param_pw(s, p->expected_user, p->pass, "1024") < 0) {
		*ad = SSL_AD_INTERNAL_ERROR;
		return SSL3_AL_FATAL;
	}

//	SSL_set_srp_server_param_pw(s, SSL_get_srp_username(s), "password", "1024");

	return SSL_ERROR_NONE;
}

static int verify_callback(int ok, X509_STORE_CTX *ctx) {
	// XXX: dummy function, but not needed, as we have no cert here!
	return ok;
}

SSL_CTX* InitServerCTX(void) {
	SSL_CTX *ctx;

	// Init OpenSSL
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	SSL_library_init();

	const SSL_METHOD *method = TLSv1_server_method();
	ctx = SSL_CTX_new(method);
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		abort();
	}

	// FIXME: needed?
	SSL_CTX_SRP_CTX_init(ctx);

	// set cipher list
	// we only want SRP algorithms without any ceritificates
	if (SSL_CTX_set_cipher_list(ctx, "aNULL:!eNULL:!LOW:!EXPORT:@STRENGTH:!ADH:!AECDH") != 1) {
		printf("SSL_CTX_set_cipher_list failed\n");
	}

	// set callbacks and give the parameters (username,password) to the context
	SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,verify_callback);
	SSL_CTX_set_srp_cb_arg(ctx, &srp_server_arg);
	SSL_CTX_set_srp_username_callback(ctx, ssl_srp_server_param_cb);

	return ctx;
}

void sslConnection(SSL* ssl) {
	char buf[1024];
	char reply[1024];
	int sd, bytes;
	const char* echo = "I received %s :)\nWelcome here!";

	int error = SSL_get_error(ssl, SSL_accept(ssl)); // start SSL and do Handshake

	if (error != SSL_ERROR_NONE) {
		ERR_print_errors_fp (stderr);
		printf("Error accepting SSL connection (%d)\n", error);
	} else { // connection established successfully -> do some dummy communication
		bytes = SSL_read(ssl, buf, sizeof(buf));
		if (bytes > 0) {
			buf[bytes] = 0;
			printf("Client msg: \"%s\"\n", buf);
			sprintf(reply, echo, buf);
			SSL_write(ssl, reply, strlen(reply));
		} else {
			ERR_print_errors_fp(stderr);
		}
	}
	sd = SSL_get_fd(ssl);
	SSL_free(ssl);
	close(sd);
}

int main(int argc, char **argv) {

	if (argc < 2) {
		printf("Usage: ./server <port>\n");
		return 1;
	}

	SSL_CTX *ctx;
	int server;

	// Create SSL Context
	ctx = InitServerCTX();

	// Listen on socket
	server = startServerListener(atoi(argv[1]));

	// keep port open until server is closed with CTRL+C
	while (1) {
		struct sockaddr_in addr;
		socklen_t len = sizeof(addr);
		SSL *ssl;

		// open socket connection to client
		int client = accept(server, (struct sockaddr*)&addr, &len);

		// get SSL from context
		ssl = SSL_new(ctx);
		printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

		// connect SSL to client socket connection
		SSL_set_fd(ssl, client);

		// start SSL connection (including handshake and stuff)
		sslConnection(ssl);
	}
	close(server);
	SSL_CTX_free(ctx);
}
