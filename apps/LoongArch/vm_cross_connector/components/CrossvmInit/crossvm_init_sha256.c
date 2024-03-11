/*
 * Copyright 2019, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <string.h>
#include <camkes.h>

#include "sha256/sha256.h"

unsigned char data[4194304];
uint8_t hash[SHA256_SIZE_BYTES];

int r = 1010;

int run(void)
{
    memset(dest, '\0', 4194304);
    strcpy(dest, "This is a crossvm dataport test string\n");
    

    printf("crossvm_init_sha256\n");

    while (1) {

        for (int j = 0; j < r; ++j) {
            ready_wait();

            memcpy(data, dest, 16);
            
            sha256(data, 16, hash);

            memcpy(dest, hash, 256);
            memcpy(dest, hash, 256);

            done_emit_underlying();
        }

        for (int j = 0; j < r; ++j) {
            ready_wait();

            memcpy(data, dest, 32);
            
            sha256(data, 32, hash);

            memcpy(dest, hash, 256);
            memcpy(dest, hash, 256);

            done_emit_underlying();
        }

        for (int j = 0; j < r; ++j) {
            ready_wait();

            memcpy(data, dest, 64);
            
            sha256(data, 64, hash);

            memcpy(dest, hash, 256);
            memcpy(dest, hash, 256);

            done_emit_underlying();
        }

        for (int j = 0; j < r; ++j) {
            ready_wait();

            memcpy(data, dest, 128);
            
            sha256(data, 128, hash);

            memcpy(dest, hash, 256);
            memcpy(dest, hash, 256);

            done_emit_underlying();
        }

        for (int j = 0; j < r; ++j) {
            ready_wait();

            memcpy(data, dest, 256);
            
            sha256(data, 256, hash);

            memcpy(dest, hash, 256);
            memcpy(dest, hash, 256);

            done_emit_underlying();
        }
        
        for (int j = 0; j < r; ++j) {
            ready_wait();

            memcpy(data, dest, 512);
            
            sha256(data, 512, hash);

            memcpy(dest, hash, 256);
            memcpy(dest, hash, 256);

            done_emit_underlying();
        }

        for (int j = 0; j < r; ++j) {
            ready_wait();

            memcpy(data, dest, 1024);
            
            sha256(data, 1024, hash);

            memcpy(dest, hash, 256);
            memcpy(dest, hash, 256);

            done_emit_underlying();
        }

        for (int j = 0; j < r; ++j) {
            ready_wait();

            memcpy(data, dest, 4096);
            
            sha256(data, 4096, hash);

            memcpy(dest, hash, 256);
            memcpy(dest, hash, 256);

            done_emit_underlying();
        }

        for (int j = 0; j < r; ++j) {
            ready_wait();

            memcpy(data, dest, 32768);
            
            sha256(data, 32768, hash);

            memcpy(dest, hash, 256);
            memcpy(dest, hash, 256);

            done_emit_underlying();
        }

        for (int j = 0; j < r; ++j) {
            ready_wait();

            memcpy(data, dest, 524288);
            
            sha256(data, 524288, hash);

            memcpy(dest, hash, 256);
            memcpy(dest, hash, 256);

            done_emit_underlying();
        }

        for (int j = 0; j < r; ++j) {
            ready_wait();

            memcpy(data, dest, 1048576);
            
            sha256(data, 1048576, hash);

            memcpy(dest, hash, 256);
            memcpy(dest, hash, 256);

            done_emit_underlying();
        }

        for (int j = 0; j < r; ++j) {
            ready_wait();

            memcpy(data, dest, 2097152);
            
            sha256(data, 2097152, hash);

            memcpy(dest, hash, 256);
            memcpy(dest, hash, 256);

            done_emit_underlying();
        }

        for (int j = 0; j < r; ++j) {
            ready_wait();

            memcpy(data, dest, 4194304);
            
            sha256(data, 4194304, hash);

            memcpy(dest, hash, 256);
            memcpy(dest, hash, 256);

            done_emit_underlying();
        }
    }

    return 0;
}
