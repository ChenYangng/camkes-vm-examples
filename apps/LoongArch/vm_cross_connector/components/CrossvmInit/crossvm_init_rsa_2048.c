/*
 * Copyright 2019, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <string.h>
#include <camkes.h>

#include "rsa/rsa.h"
#include "rsa/keys2048.h"

int r = 10010;

rsa_pk_t pk = {0};
rsa_sk_t sk = {0};
uint8_t output[256];

// message to encrypt
uint8_t input [256] = { 0x21,0x55,0x53,0x53,0x53,0x53};

unsigned char msg [256];
uint32_t outputLen, msg_len;
uint8_t  inputLen;

/*
 * RSA2048 encrypt and decrypt
 * include rsa.c/bignum.c/rsa.h/bignum.h/keys.h
 */
static int RSA2048(void){

    // copy keys.h message about public key and private key to the flash RAM
    pk.bits = KEY_M_BITS;
    memcpy(&pk.modulus         [RSA_MAX_MODULUS_LEN-sizeof(key_m) ],  key_m,  sizeof(key_m ));
    memcpy(&pk.exponent        [RSA_MAX_MODULUS_LEN-sizeof(key_e) ],  key_e,  sizeof(key_e ));
    sk.bits = KEY_M_BITS;
    memcpy(&sk.modulus         [RSA_MAX_MODULUS_LEN-sizeof(key_m) ],  key_m,  sizeof(key_m ));
    memcpy(&sk.public_exponet  [RSA_MAX_MODULUS_LEN-sizeof(key_e) ],  key_e,  sizeof(key_e ));
    memcpy(&sk.exponent        [RSA_MAX_MODULUS_LEN-sizeof(key_pe)],  key_pe, sizeof(key_pe));
    memcpy(&sk.prime1          [RSA_MAX_PRIME_LEN - sizeof(key_p1)],  key_p1, sizeof(key_p1));
    memcpy(&sk.prime2          [RSA_MAX_PRIME_LEN - sizeof(key_p2)],  key_p2, sizeof(key_p2));
    memcpy(&sk.prime_exponent1 [RSA_MAX_PRIME_LEN - sizeof(key_e1)],  key_e1, sizeof(key_e1));
    memcpy(&sk.prime_exponent2 [RSA_MAX_PRIME_LEN - sizeof(key_e2)],  key_e2, sizeof(key_e2));
    memcpy(&sk.coefficient     [RSA_MAX_PRIME_LEN - sizeof(key_c) ],  key_c,  sizeof(key_c ));

    inputLen = strlen((const char*)input);

    return 0;
}

/* RSA2048 function ended */
int run(void)
{
    memset(dest, '\0', 4194304);
    strcpy(dest, "This is a crossvm dataport test string\n");


    RSA2048();

    while (1) {
        // encrypt
        for (int j = 0; j < r; ++j) {
            ready_wait();
            
            // public key encrypt
            // rsa_public_encrypt(output, &outputLen, input, inputLen, &pk);

            // private key encrypt
            rsa_private_encrypt(msg, &msg_len, output, outputLen, &sk);

            done_emit_underlying();
        }

        // decrypt
        for (int j = 0; j < r; ++j) {
            ready_wait();
            
            // public key encrypt
            // rsa_private_decrypt(msg, &msg_len, output, outputLen, &sk);

            // public key decrypt
            rsa_public_decrypt(output, &outputLen, input, inputLen, &pk);

            done_emit_underlying();
        }
    }

    return 0;
}
