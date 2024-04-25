/*
 * Copyright 2019, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <string.h>
#include <camkes.h>

int r = 10010;

int run(void)
{
    memset(dest, '\0', 4194304);
    strcpy(dest, "This is a crossvm dataport test string\n");

    while (1) {
        for (int j = 0; j < r; ++j) {
            ready_wait();
            done_emit_underlying();
        }
    }

    return 0;
}
