/*
 * C Macros implementing the basic ARCFOUR algorithm for shared use in
 * different applications.
 *
 * Version 2020.359
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

#define ARCFOUR_VARDEFS(storage_class) \
   storage_class struct { \
      unsigned char s[SBOX_SIZE], v1, v2; \
      unsigned i, j; \
   } r4
#define ARCFOUR_STEP_1_KEY for (r4.i= SBOX_SIZE; r4.i-- ; ) \
   r4.s[r4.i]= (unsigned char)r4.i
#define ARCFOUR_STEP_2 r4.i= r4.j= 0
#define ARCFOUR_STEP_3_PRNG r4.i= SBOX_MOD(r4.i + 1)
#define ARCFOUR_STEP_4_KEY(keyoctet) \
   r4.j= SBOX_MOD(r4.j + r4.s[r4.i] + (keyoctet))
#define ARCFOUR_STEP_4_PRNG r4.j= SBOX_MOD(r4.j + r4.s[r4.i])
#define ARCFOUR_STEP_5_DROP r4.v1= r4.s[r4.i]; \
   r4.s[r4.i]= r4.s[r4.j]; r4.s[r4.j]= r4.v1
#define ARCFOUR_STEP_5_PRNG r4.v1= r4.s[r4.i]; \
   r4.s[r4.i]= r4.v2= r4.s[r4.j]; r4.s[r4.j]= r4.v1
#define ARCFOUR_STEP_6_PRNG() r4.s[SBOX_MOD(r4.v1 + r4.v2)]
#define ARCFOUR_STEP_7_KEY r4.i= SBOX_MOD(r4.i + 1)
