/*
 * spake.c
 *
 *  Created on: 13.10.2013
 *      Author: Franziskus Kiefer
 */
#include "spake.h"

/*
 * initialise spake session
 */
struct spake_session spake_init(int role, gcry_mpi_t g, gcry_mpi_t p, gcry_mpi_t M, gcry_mpi_t N, gcry_mpi_t pwd, int keySize) {
	struct spake_session session;
	gcry_mpi_t t;

	t = gcry_mpi_new(0);
	session.x = gcry_mpi_new(0);
	session.X = gcry_mpi_new(0);

	session.role = role;
	session.g = g;
	session.p = p;
	session.M = M;
	session.N = N;
	session.pwd = pwd;
	session.keySize = keySize;

	/* make dh key-pair */
	gen_rand(session.x, p);
	gcry_mpi_powm(session.X, g, session.x, p);

	/* create X* */
	if (role == 0) { /* client */
		gcry_mpi_powm(t, M, pwd, p);
		gcry_mpi_mulm(session.X, session.X, t, p);
	} else { /* server */
		gcry_mpi_powm(t, N, pwd, p);
		gcry_mpi_mulm(session.X, session.X, t, p);
	}

	return session;
}

/*
 * generate session key
 */
void spake_next(struct spake_session* session, gcry_mpi_t Y) {
	gcry_mpi_t k;
	k = gcry_mpi_new(0);
	unsigned char *tmp;
	size_t tmpSize;
	gcry_mpi_t t;

	t = gcry_mpi_new(0);

	/* calculate key */
	if (session->role == 0) { /* client */
		gcry_mpi_powm(t, session->N, session->pwd, session->p);
	} else { /* server */
		gcry_mpi_powm(t, session->M, session->pwd, session->p);
	}
	gcry_mpi_invm(t, t, session->p);
	gcry_mpi_mulm(k, Y, t, session->p);
	gcry_mpi_powm(k, k, session->x, session->p);

	/* hash it */
	gcry_md_hd_t hd;
    gcry_md_open(&hd, GCRY_MD_SHA256, 0);
 
	gcry_md_write(hd, "C", 1);
	gcry_md_write(hd, "S", 1);

	if (session->role == 0) { /* client */
		gcry_mpi_aprint(GCRYMPI_FMT_HEX, &tmp, &tmpSize, session->X);
		gcry_md_write(hd, tmp, tmpSize);

		gcry_mpi_aprint(GCRYMPI_FMT_HEX, &tmp, &tmpSize, Y);
		gcry_md_write(hd, tmp, tmpSize);
	} else { /* server */
		gcry_mpi_aprint(GCRYMPI_FMT_HEX, &tmp, &tmpSize, Y);
		gcry_md_write(hd, tmp, tmpSize);
	
		gcry_mpi_aprint(GCRYMPI_FMT_HEX, &tmp, &tmpSize, session->X);
		gcry_md_write(hd, tmp, tmpSize);
	}

	gcry_mpi_aprint(GCRYMPI_FMT_HEX, &tmp, &tmpSize, session->pwd);
	gcry_md_write(hd, tmp, tmpSize);
	
	gcry_mpi_aprint(GCRYMPI_FMT_HEX, &tmp, &tmpSize, k);
	gcry_md_write(hd, tmp, tmpSize);

	unsigned char* pi = gcry_md_read(hd, GCRY_MD_SHA256);
	session->k = calloc(session->keySize, sizeof(unsigned char));
    memcpy((char*)session->k, pi, session->keySize);
    gcry_md_close(hd);
	
}
