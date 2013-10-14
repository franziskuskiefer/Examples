#include "spake.h"

int main(int argc, char *argv[]) {
	gcry_mpi_t g,p,M,N,pw,t1,t2;
	size_t scanned;
	int iterations, keySize;

	g = gcry_mpi_new(0);
	p = gcry_mpi_new(0);
	M = gcry_mpi_new(0);
	N = gcry_mpi_new(0);
	pw = gcry_mpi_new(0);
	t1 = gcry_mpi_new(0);
	t2 = gcry_mpi_new(0);

	/* MODP_2048 */
	const char* pString = "00FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";
	const char* gString = "2";

	/* password */
	const char* pwd = "My$Very=Secure;Password";
	const char* salt = "abcdefghijklmno";
	iterations = 1000;
	keySize = 32;	
	
	/* read p and g */
	gcry_mpi_scan(&g, GCRYMPI_FMT_HEX, gString, 0, &scanned);
	gcry_mpi_scan(&p, GCRYMPI_FMT_HEX, pString, 0, &scanned);

	/* hash password */
	char* result = calloc(keySize, sizeof(char));
	gcry_kdf_derive(pwd, strlen(pwd), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, strlen(salt), iterations, keySize, result);
	gcry_mpi_scan(&pw, GCRYMPI_FMT_STD, result, strlen((const char*)result), &scanned);

	/* create M and N */
	gen_rand(t1, p);
	gen_rand(t2, p);
	gcry_mpi_powm(M, g, t1, p);
	gcry_mpi_powm(N, g, t2, p);

	/* run test ... */
	struct spake_session client = spake_init(0, g, p, M, N, pw, keySize); /* client */
	struct spake_session server = spake_init(1, g, p, M, N, pw, keySize); /* server */

	spake_next(&client, server.X);
	spake_next(&server, client.X);

	print_key(client.k, keySize, "k1");
	print_key(server.k, keySize, "k2");

	if (strncmp(client.k, server.k, keySize) == 0)
		printf("Successful SPAKE session :)\n");
	else
		printf("Sorry, error in SPAKE session :(\n");
	
	return 0;
}