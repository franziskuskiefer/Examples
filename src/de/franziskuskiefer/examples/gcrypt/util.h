/*
 * util.h
 *
 *  Created on: 14.10.2013
 *      Author: Franziskus Kiefer
 * 
 */

#ifndef UTIL_H_
#define UTIL_H_

#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>

#ifdef __cplusplus
extern "C" {
#endif

void gen_rand(gcry_mpi_t r, gcry_mpi_t p);
void mpi_print(gcry_mpi_t x);
void print_key(const char* key, size_t keySize, const char* label);

#ifdef __cplusplus
}
#endif

#endif /* UTIL_H_ */