/* sha3.c - TinyCrypt SHA-3 crypto hash algorithm implementation */

/*
 *  Copyright (C) 2019 by Intel Corporation, All Rights Reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *    - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *    - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *    - Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#include <tinycrypt/sha3.h>
#include <tinycrypt/constants.h>
#include <tinycrypt/utils.h>

#define NumberOfRounds 24

/* state string S --> state matrix A mapping:
 * 	
 * S[0]		S[1]	S[2] 	S[3] 	S[4] 	S[5] 	S[6] 	S[7] 	S[8] 	S[9] 	S[10] 	S[11] 	S[12] 
 * A[0,0]	A[1,0]	A[2,0]	A[3,0]	A[4,0]	A[0,1]	A[1,1]	A[2,1]	A[3,1]	A[4,1]	A[0,2]	A[1,2]	A[2,2]		
 * 
 * S[13] 	S[14] 	S[15] 	S[16] 	S[17] 	S[18] 	S[19] 	S[20] 	S[21] 	S[22] 	S[23] 	S[24]
 * A[3,2]	A[4,2]	A[0,3]	A[1,3]	A[2,3]	A[3,3]	A[4,3]	A[0,4]	A[1,4]	A[2,4]	A[3,4]	A[4,4]
 * 
 */

static inline uint64_t ROTL64(uint64_t a, uint64_t n)
{
	return (((a) << n) | ((a) >> (64 - n)));
}


/* θ step mapping */
static void theta(uint64_t S[TC_SHA3_PERMUTATION_WIDTH])
{
	uint64_t C[5];
	uint64_t D[5];

	/* C[x] = A[x,0] ^ A [x, 1] ^ A[x, 2] ^ A[x, 3] ^ A[x, 4]; */

	C[0] = S[0] ^ S[0 + 5] ^ S[0 + 10] ^ S[0 + 15] ^ S[0 + 20];
	C[1] = S[1] ^ S[1 + 5] ^ S[1 + 10] ^ S[1 + 15] ^ S[1 + 20];
	C[2] = S[2] ^ S[2 + 5] ^ S[2 + 10] ^ S[2 + 15] ^ S[2 + 20];
	C[3] = S[3] ^ S[3 + 5] ^ S[3 + 10] ^ S[3 + 15] ^ S[3 + 20];
	C[4] = S[4] ^ S[4 + 5] ^ S[4 + 10] ^ S[4 + 15] ^ S[4 + 20];

	/* D[x] = C[(x-1)mod 5] ^ C[(x+1)mod 5] */

	/* D[0] = C[ -1 mod 5] ^ C[1 mod 5] */
	/* D[1] = C[ 0 mod 5]  ^ C[2 mod 5] */
	/* D[2] = C[ 1 mod 5]  ^ C[3 mod 5] */
	/* D[3] = C[ 2 mod 5]  ^ C[4 mod 5] */
	/* D[4] = C[ 3 mod 5]  ^ C[5 mod 5] */

	D[0] = C[4] ^ ROTL64(C[1], 1);
	D[1] = C[0] ^ ROTL64(C[2], 1);
	D[2] = C[1] ^ ROTL64(C[3], 1);
	D[3] = C[2] ^ ROTL64(C[4], 1);
	D[4] = C[3] ^ ROTL64(C[0], 1);


	/* A'[x,y] = A[x,y] ^ D[x] */

	S[0]      ^= D[0]; 
	S[0 + 5]  ^= D[0]; 
	S[0 + 10] ^= D[0]; 
	S[0 + 15] ^= D[0]; 
	S[0 + 20] ^= D[0];

	S[1]      ^= D[1];
	S[1 + 5]  ^= D[1];
	S[1 + 10] ^= D[1];
	S[1 + 15] ^= D[1];
	S[1 + 20] ^= D[1]; 

	S[2]      ^= D[2];
	S[2 + 5]  ^= D[2];
	S[2 + 10] ^= D[2];
	S[2 + 15] ^= D[2];
	S[2 + 20] ^= D[2];

	S[3]      ^= D[3];
	S[3 + 5]  ^= D[3];
	S[3 + 10] ^= D[3];
	S[3 + 15] ^= D[3];
	S[3 + 20] ^= D[3];

	S[4]      ^= D[4];
	S[4 + 5]  ^= D[4];
	S[4 + 10] ^= D[4];
	S[4 + 15] ^= D[4];
	S[4 + 20] ^= D[4];

} 


int rho_offsets[TC_SHA3_PERMUTATION_WIDTH] =  {
    0 , 1 , 62, 28, 27, 36, 44, 6, 55, 20, 3, 10,
    43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14};


/* ρ step mapping */
static void rho(uint64_t S[TC_SHA3_PERMUTATION_WIDTH])
{
    for(unsigned int i = 0; i < TC_SHA3_PERMUTATION_WIDTH; ++i) 
        S[i] = ROTL64(S[i], rho_offsets[i]);
}

/* π step mapping */
static void pi(uint64_t S[TC_SHA3_PERMUTATION_WIDTH])
{
	uint64_t S_1;
	S_1 = S[1];
	
	/* A'[x,y] = A[(x+3y)mod 5,x] */

	/* A'[0,0] = A[0,0] */
	/* A'[1,0] = A[1,1] */
	/* A'[1,1] = A[4,1] */
	/* ... */

	S[0] = S[0];
	S[1] = S[6];
	S[6] = S[9];
	S[9] = S[22];
	S[22] = S[14];
	S[14] = S[20];
	S[20] = S[2];
	S[2] = S[12];
	S[12] = S[13];
	S[13] = S[19];
	S[19] = S[23];
	S[23] = S[15];
	S[15] = S[4];
	S[4] = S[24];
	S[24] = S[21];
	S[21] = S[8];
	S[8] = S[16];
	S[16] = S[5];
	S[5] = S[3];
	S[3] = S[18];
	S[18] = S[17];
	S[17] = S[11];
	S[11] = S[7];
	S[7] = S[10];
	S[10] = S_1;

}

/* χ state mapping */
static void chi(uint64_t S[TC_SHA3_PERMUTATION_WIDTH])
{
	uint64_t S_0, S_1;

	/* A'[x,y] = A[x,y] ^ ((A[(x+1)mod 5, y] ^ 1) & A[(x+2)mod 5, y]) */
	/* A'[x,y] = A[x,y] ^ (~(A[(x+1)mod 5, y]) & A[(x+2)mod 5, y]) */

	/* A'[0,0] = A[0,0] ^ (~(A[1, 0]) & A[2, 0]) */
	/* A'[1,0] = A[1,0] ^ (~(A[2, 0]) & A[3, 0]) */
	/* A'[2,0] = A[2,0] ^ (~(A[3, 0]) & A[4, 0]) */
	/* A'[3,0] = A[3,0] ^ (~(A[4, 0]) & A[0, 0]) */
	/* A'[4,0] = A[4,0] ^ (~(A[0, 0]) & A[1, 0]) */

	S_0 = S[0];
	S_1 = S[1];

	S[0] ^= ~S_1 & S[2];
	S[1] ^= ~S[2] & S[3];
	S[2] ^= ~S[3] & S[4];
	S[3] ^= ~S[4] & S_0;
	S[4] ^= ~S_0 & S_1;

	S_0 = S[5];
	S_1 = S[6];

	S[5] ^= ~S_1 & S[7];
	S[6] ^= ~S[7] & S[8];
	S[7] ^= ~S[8] & S[9];
	S[8] ^= ~S[9] & S_0;
	S[9] ^= ~S_0 & S_1;

	S_0 = S[10];
	S_1 = S[11];

	S[10] ^= ~S_1 & S[12];
	S[11] ^= ~S[12] & S[13];
	S[12] ^= ~S[13] & S[14];
	S[13] ^= ~S[14] & S_0;
	S[14] ^= ~S_0 & S_1;

	S_0 = S[15];
	S_1 = S[16];

	S[15] ^= ~S_1 & S[17];
	S[16] ^= ~S[17] & S[18];
	S[17] ^= ~S[18] & S[19];
	S[18] ^= ~S[19] & S_0;
	S[19] ^= ~S_0 & S_1;

	S_0 = S[20];
	S_1 = S[21];

	S[20] ^= ~S_1 & S[22];
	S[21] ^= ~S[22] & S[23];
	S[22] ^= ~S[23] & S[24];
	S[23] ^= ~S[24] & S_0;
	S[24] ^= ~S_0 & S_1;


}

static uint64_t iotas[NumberOfRounds] = {
	0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808AUL, 0x8000000080008000UL,
	0x000000000000808BUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
	0x000000000000008AUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000AUL,
	0x000000008000808BUL, 0x800000000000008BUL, 0x8000000000008089UL, 0x8000000000008003UL,
	0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800AUL, 0x800000008000000AUL,
	0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
};

static void absorb(TCSha3State_t s)
{

	/* xor block of data with accumulating hash */
	for (unsigned int i = 0; i < s->block_size/8; ++i)
		s->S[i] ^= s->leftover[i];


	/* do kessak-p-transformation */
	for (int round = 0; round < NumberOfRounds; ++round)
	{
		theta(s->S);

		rho(s->S);

		pi(s->S);

		chi(s->S);

		s->S[0] ^= iotas[round];

	}
}

int tc_sha3_init(TCSha3State_t s, unsigned int bitsize)
{

	/* input sanity check: */
	if (s == (TCSha3State_t) 0) {
		return TC_CRYPTO_FAIL;
	}

	/* Sha3 sub-variant sanity check: */
	if ((bitsize != TC_SHA3_224) &&
		(bitsize != TC_SHA3_256) &&
		(bitsize != TC_SHA3_384) &&
		(bitsize != TC_SHA3_512)) {
		return TC_CRYPTO_FAIL;
	}

	_set((uint8_t *) s, 0x00, sizeof(*s));

	s->block_size = (1600 - bitsize * 2) / 8;

	return TC_CRYPTO_SUCCESS;
}

int tc_sha3_update(TCSha3State_t s, const uint8_t *data, size_t datalen)
{
	/* input sanity check: */
	if (s == (TCSha3State_t) 0 ||
	    data == (void *) 0 ) {
		return TC_CRYPTO_FAIL;
	} else if (datalen == 0) {
		return TC_CRYPTO_SUCCESS;
	}

	while (datalen-- > 0) {
		((uint8_t *)s->leftover)[s->leftover_offset++] = *(data++);
		if (s->leftover_offset >= s->block_size) {
			absorb(s);
			s->leftover_offset = 0;
		}
	}

	return TC_CRYPTO_SUCCESS;
}

int tc_sha3_final(uint8_t *digest, TCSha3State_t s)
{
	size_t digest_length = 100 - s->block_size / 2;

	/* input sanity check: */
	if (digest == (uint8_t *) 0 ||
	    s == (TCSha3State_t) 0 ) {
		return TC_CRYPTO_FAIL;
	}
	
	_set((uint8_t *)s->leftover + s->leftover_offset, 0x00,
		     sizeof(s->leftover) - s->leftover_offset);
	((uint8_t *)s->leftover)[s->leftover_offset] |= 0x06; /* 01 (sha3 padding) || 100000 (begining of 10*1 padding) */
	((uint8_t *)s->leftover)[s->block_size - 1] |= 0x80;  /* 00000001 (end of 10*1 padding) */

	absorb(s);

	/* copy the S out to digest */
	for (unsigned int i = 0; i < digest_length; ++i) {
		*digest++ = (uint8_t) ((uint8_t *)s->S)[i];
	}

	/* destroy the current state */
	_set(s, 0, sizeof(*s));

	return TC_CRYPTO_SUCCESS;
}




