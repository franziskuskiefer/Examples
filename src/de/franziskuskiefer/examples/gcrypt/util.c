/*
 * util.c
 *
 *  Created on: 14.10.2013
 *      Author: Franziskus Kiefer
 */

#include "util.h"

/*
 * Generate a random number less than p
 * FIXME: takes ages ...
 */
void gen_rand(gcry_mpi_t r, gcry_mpi_t p) {
	do {
		gcry_mpi_randomize(r, gcry_mpi_get_nbits(p), GCRY_STRONG_RANDOM);
		gcry_mpi_clear_highbit(r, gcry_mpi_get_nbits(p) + 1);
	} while (gcry_mpi_cmp(p, r) < 0);
}

/*
 * print mpi to std out
 */
void mpi_print(gcry_mpi_t x) {
	unsigned char buf[10000];
	size_t nbytes = 0;
	unsigned int i;
	gcry_mpi_print(GCRYMPI_FMT_HEX, buf, sizeof(buf), &nbytes, x);
	for (i = 0; i < nbytes - 1; i++)
		printf("%c", buf[i]);
	printf("\n");
}

/*
 * print a char array with label
 */
void print_key(const char* key, size_t keySize, const char* label) {
	int i=0;
	printf("%s: ",label);
	while (i < keySize)
		printf("%02X", key[i++] & 0xff);
	printf("\n");
}