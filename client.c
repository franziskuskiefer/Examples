//SSL-Client.c
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

#define FAIL    -1

/* SRP client */
/* This is a context that we pass to all callbacks */
typedef struct srp_arg_st {
	char *srppassin;
	char *srplogin;
	int msg; /* copy from c_msg */
	int debug; /* copy from c_debug */
	int amp; /* allow more groups */
	int strength /* minimal size for N */;
} SRP_CLIENT_ARG;

int OpenConnection(const char *hostname, int port) {
	int sd;
    struct hostent *host;
    struct sockaddr_in addr;

	if ((host = gethostbyname(hostname)) == NULL) {
		perror(hostname);
		abort();
	}
	sd = socket(PF_INET, SOCK_STREAM, 0);
//	bzero(&addr, sizeof(addr));
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
	// FIXME: arg is empty...
//	SRP_CLIENT_ARG *srp_client_arg = (SRP_CLIENT_ARG *)arg;
//	int i;
//	for (i = 0; i < 10; ++i){
//		printf("Password[%d]: %lu\n", i, (unsigned long)srp_client_arg->srppassin[i]);
//	}
//	return BUF_strdup((char *)srp_client_arg->srppassin);
	char* pwd = "pwd";
	return BUF_strdup(pwd);
}

SSL_CTX* InitCTX(void) {
	SSL_CTX *ctx;
	// for srp callbacks
	SRP_CLIENT_ARG srp_client_arg = {"pwd","user",0,0,0,1024};

    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    SSL_library_init();
    const SSL_METHOD *method = TLSv1_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		abort();
	}
	// XXX: what does this?
//	SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);
	// SRP
	SSL_CTX_SRP_CTX_init(ctx);
	// set cipher list
	if (SSL_CTX_set_cipher_list(ctx, "aNULL:!eNULL:!LOW:!EXPORT:@STRENGTH:!ADH:!AECDH") != 1){
		printf("SSL_CTX_set_cipher_list failed");
	}

    // set SRP stuff (user and password)
    if (SSL_CTX_set_srp_username(ctx, srp_client_arg.srplogin) != 1){
    	printf("SSL_CTX_set_srp_username failed");
    	ERR_print_errors_fp(stderr);
    }

    SSL_CTX_set_srp_cb_arg(ctx,&srp_client_arg);
    SSL_CTX_set_srp_client_pwd_callback(ctx, ssl_give_srp_client_pwd_cb);
    SSL_CTX_set_srp_strength(ctx, srp_client_arg.strength);
//    if (srp_client_arg.msg || srp_client_arg.debug || srp_client_arg.amp == 0)
//    	SSL_CTX_set_srp_verify_param_callback(ctx, ssl_srp_verify_param_cb);

//    if (SSL_CTX_set_srp_password(ctx, (char *) "password") != 1){
//    	printf("SSL_CTX_set_srp_password failed");
//    	ERR_print_errors_fp(stderr);
//    }
//
//    if (SSL_CTX_set_srp_strength(ctx, 1024) != 1){
//    	printf("SSL_CTX_set_srp_strength failed");
//    	ERR_print_errors_fp(stderr);
//    }

	return ctx;
}

int main(int argc, char **argv) {
	if (argc < 2) {
		printf("Usage: ./server <server> <port>\n");
		return 1;
	}

	SSL_CTX *ctx;
	int server;
	SSL *ssl;
	char buf[1024];
    int bytes;

    ctx = InitCTX();

    server = OpenConnection(argv[1], atoi(argv[2]));
    printf("Connected to %s:%s\n", argv[1],argv[2]);

    ssl = SSL_new(ctx);      /* create new SSL connection state */
    printf("Created ssl from ctx\n");



//    STACK_OF(SSL_CIPHER) *ciphers = SSL_get_ciphers(ssl);
//    while (sk_SSL_CIPHER_num(ciphers) > 0) {
//    	SSL_CIPHER *c = sk_SSL_CIPHER_pop(ciphers);
//    	printf("%s\n",SSL_CIPHER_get_name(c));
////    	sk_SSL_CIPHER_push(ciphers, c);
//    }

    SSL_set_fd(ssl, server);    /* attach the socket descriptor */
    printf("attached ssl to socket\n");

    int error = SSL_get_error(ssl, SSL_connect(ssl));

    if (error != SSL_ERROR_NONE) {    /* do SSL-protocol accept SSL_connect(ssl) != 1*/
    	ERR_print_errors_fp (stderr);
    	printf("Error opening SSL connection: %d\n", error);
    } else {
    	printf("Successfully connected to Server via SSL\n");
		char *msg = "Hello???";

		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		SSL_write(ssl, msg, strlen(msg)); /* encrypt & send message */
		bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
		buf[bytes] = 0;
		printf("Received: \"%s\"\n", buf);
		SSL_free(ssl); /* release connection state */
	}
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    return 0;
}
