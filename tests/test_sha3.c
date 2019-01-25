/*  test_sha3.c - TinyCrypt implementation of some SHA-3 tests */

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

/*
  DESCRIPTION
  This module tests the following SHA3 routines:

  Scenarios tested include:
  - NIST SHA3 test vectors
*/

#include <tinycrypt/sha3.h>
#include <tinycrypt/sha256.h>
#include <tinycrypt/constants.h>
#include <test_utils.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/*
 * NIST SHA3 256 test vector 1.
 */
unsigned int test_1(void)
{
        unsigned int result = TC_PASS;

        TC_PRINT("SHA3 256 test #1:\n");
        const uint8_t expected[32] = {
		0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d,
		0x6b, 0xd3, 0x90, 0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
		0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32
        };

        const char *m = "abc";
        unsigned char digest[32];
        struct tc_sha3_state_struct s;

        (void)tc_sha3_init(&s, TC_SHA3_256);
        tc_sha3_update(&s, (const uint8_t *) m, strlen(m));
        (void)tc_sha3_final((uint8_t *)(&digest), &s);
        result = check_result(1, expected, sizeof(expected),
			      digest, sizeof(digest));
        TC_END_RESULT(result);
        return result;
}

/*
 * NIST SHA3 256 test vector 2
 */
unsigned int test_2(void)
{
        unsigned int result = TC_PASS;
        TC_PRINT("SHA3 256 test #2:\n");
        const uint8_t expected[32] = {
		0x41, 0xc0, 0xdb, 0xa2, 0xa9, 0xd6, 0x24, 0x08, 0x49, 0x10, 0x03, 0x76,
		0xa8, 0x23, 0x5e, 0x2c, 0x82, 0xe1, 0xb9, 0x99, 0x8a, 0x99, 0x9e, 0x21,
		0xdb, 0x32, 0xdd, 0x97, 0x49, 0x6d, 0x33, 0x76
        };

        const char *m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        uint8_t digest[32];
        struct tc_sha3_state_struct s;

        (void)tc_sha3_init(&s, TC_SHA3_256);
        tc_sha3_update(&s, (const uint8_t *) m, strlen(m));
        (void) tc_sha3_final(digest, &s);

        result = check_result(2, expected, sizeof(expected),
			      digest, sizeof(digest));
        TC_END_RESULT(result);
        return result;
}


/*
 * Main task to test AES
 */

int main(void)
{
        unsigned int result = TC_PASS;
        TC_START("Performing SHA-3 tests (NIST tests vectors):");

        result = test_1();
        if (result == TC_FAIL) {
		/* terminate test */
                TC_ERROR("SHA-3 256 test #1 failed.\n");
                goto exitTest;
        }
        result = test_2();
        if (result == TC_FAIL) {
		/* terminate test */
                TC_ERROR("SHA256 test #2 failed.\n");
                goto exitTest;
        }
        
        TC_PRINT("All SHA3 256 tests succeeded!\n");

exitTest:
        TC_END_RESULT(result);
        TC_END_REPORT(result);
}

