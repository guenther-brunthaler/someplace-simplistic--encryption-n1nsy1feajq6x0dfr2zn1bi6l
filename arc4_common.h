/*
 * C Macros implementing the basic ARCFOUR algorithm for shared use in
 * different applications.
 *
 * Version 2020.335
 *
 * Copyright (c) 2020 Guenther Brunthaler. All rights reserved.
 *
 * This source file is free software.
 * Distribution is permitted under the terms of the GPLv3.
 */

#define SCAN_DEFAULT (3 * SBOX_SIZE)
#define DROP_N (4 * SCAN_DEFAULT)

#define SBOX_SIZE (1 << 8)
#define SBOX_MOD(x) ((x) & SBOX_SIZE - 1)

#define ARCFOUR_VARDEFS(stclass) \
   stclass unsigned char s[SBOX_SIZE], v1, v2; \
   unsigned i, j
#define ARCFOUR_STEP_1 for (i= SBOX_SIZE; i-- ;) s[i]= (unsigned char)i
#define ARCFOUR_STEP_2 i= j= 0
#define ARCFOUR_STEP_3 i= SBOX_MOD(i + 1)
#define ARCFOUR_STEP_4_SETUP(keyoctet) j= SBOX_MOD(j + s[i] + keyoctet)
#define ARCFOUR_STEP_4 j= SBOX_MOD(j + s[i])
#define ARCFOUR_STEP_5_DROP v1= s[i]; s[i]= s[j]; s[j]= v1
#define ARCFOUR_STEP_5 v1= s[i]; s[i]= v2= s[j]; s[j]= v1
#define ARCFOUR_STEP_6() s[SBOX_MOD(v1 + v2)]
