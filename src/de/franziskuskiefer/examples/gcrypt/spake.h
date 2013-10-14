/*
 * spake.h
 *
 *  Created on: 13.10.2013
 *      Author: Franziskus Kiefer
 * 
 * SPAKE protocol according to http://www.di.ens.fr/~abdalla/papers/AbPo05a-letter.pdf
 * 
 */

#ifndef SPAKE_H_
#define SPAKE_H_

#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>

#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEBUG 1
	
struct spake_session {
	int role; /* 0 := client, 1 := server */
	gcry_mpi_t g; /* group generator */
	gcry_mpi_t p; /* group modulus */
	gcry_mpi_t M; /* public constant 1 */
	gcry_mpi_t N; /* public constant 2 */
	gcry_mpi_t X; /* public key */
	gcry_mpi_t x; /* secret key */
	gcry_mpi_t pwd; /* password */
	const char* k; /* password */
	int keySize; /* key size */
};

struct spake_session spake_init(int role, gcry_mpi_t g, gcry_mpi_t p, gcry_mpi_t M, gcry_mpi_t N, gcry_mpi_t pwd, int keySize);
void spake_next(struct spake_session* session, gcry_mpi_t Y);

#ifdef __cplusplus
}
#endif

#endif /* SPAKE_H_ */