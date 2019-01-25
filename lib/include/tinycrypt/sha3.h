/* sha3.h - TinyCrypt interface to a SHA-3 implementation */

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

/**
 * @file
 * @brief Interface to a SHA-3 implementation.
 *
 *  Overview:   SHA-3 is a NIST approved cryptographic hashing algorithm
 *              specified in FIPS 202. A hash algorithm maps data of arbitrary
 *              size to data of fixed length.
 *
 *  Security:   SHA-3 provides 112 - 256 bits of security against collision attacks
 *              and 224 - 512 bits of security against pre-image attacks depending
 * 				on the sub-variant chosen. SHA-3 does NOT behave like a random oracle,
 *              but it can be used as one if
 *              the string being hashed is prefix-free encoded before hashing.
 *
 *  Usage:      1) call tc_sha3_init to choose sub-variant and initialize a struct
 *              tc_sha3_state_struct before hashing a new string.
 *
 *              2) call tc_sha3_update to hash the next string segment;
 *              tc_sha3_update can be called as many times as needed to hash
 *              all of the segments of a string; the order is important.
 *
 *              3) call tc_sha3_final to out put the digest from a hashing
 *              operation.
 */

#ifndef __TC_SHA3_H__
#define __TC_SHA3_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TC_SHA3_PERMUTATION_WIDTH (25) 
#define TC_SHA3_224 (224)
#define TC_SHA3_256 (256)
#define TC_SHA3_384 (384)
#define TC_SHA3_512 (512)

struct tc_sha3_state_struct {
	size_t block_size; /* message block size */
	uint64_t S[TC_SHA3_PERMUTATION_WIDTH]; /* internal state string - 1600 bits */
	/* 1536-bit buffer for leftovers */
	uint64_t leftover[TC_SHA3_PERMUTATION_WIDTH - 1];
	/* count of bytes in the message[] buffer */
	size_t leftover_offset;
};

typedef struct tc_sha3_state_struct *TCSha3State_t;

/**
 *  @brief SHA3 initialization procedure
 *  Initializes s
 *  @return returns TC_CRYPTO_SUCCESS (1)
 *          returns TC_CRYPTO_FAIL (0) if s == NULL
 *  @param s Sha3 state struct
 *  @param bitsize sha3 sub-variant bits
 */
int tc_sha3_init(TCSha3State_t s, unsigned int bitsize);

/**
 *  @brief SHA3 update procedure
 *  Hashes data_length bytes addressed by data into state s
 *  @return returns TC_CRYPTO_SUCCESS (1)
 *          returns TC_CRYPTO_FAIL (0) if:
 *                s == NULL,
 *                data == NULL
 *  @note Assumes s has been initialized by tc_sha3_init
 *  @warning The state buffer 'leftover' is left in memory after processing
 *           If your application intends to have sensitive data in this
 *           buffer, remind to erase it after the data has been processed
 *  @param s Sha3 state struct
 *  @param data message to hash
 *  @param datalen length of message to hash
 */
int tc_sha3_update(TCSha3State_t s, const uint8_t *data, size_t datalen);

/**
 *  @brief SHA3 final procedure
 *  Inserts the completed hash computation into digest
 *  @return returns TC_CRYPTO_SUCCESS (1)
 *          returns TC_CRYPTO_FAIL (0) if:
 *                s == NULL,
 *                digest == NULL
 *  @note Assumes: s has been initialized by tc_sha3_init
 *  @warning The state buffer 'leftover' is left in memory after processing
 *           If your application intends to have sensitive data in this
 *           buffer, remind to erase it after the data has been processed
 *  @param digest unsigned eight bit integer
 *  @param Sha3 state struct
 */
int tc_sha3_final(uint8_t *digest, TCSha3State_t s);

#ifdef __cplusplus
}
#endif

#endif /* __TC_SHA3_H__ */
