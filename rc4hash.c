/*
 * rc4hash - abuse ARCFOUR as a simplistic and reasonably fast hash algorithm
 *
 * Version 2020.322.1
 *
 * Copyright (c) 2020 Guenther Brunthaler. All rights reserved.
 *
 * This source file is free software.
 * Distribution is permitted under the terms of the GPLv3.
 */

#include "arc4_common.h"
#include <dim_sdbrke8ae851uitgzm4nv3ea2.h>
#include <getopt_nh7lll77vb62ycgwzwf30zlln.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#define ALPHABET_BITS 5
#define DIGEST_BITS 256

static char const alphabet[]= {
   /*
   $ perl -e \
   'print join(", ", map "'\'\$_\''", grep /[^01OI]/, (A..Z, 0..9)), "\n"'
   */
     'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'
   , 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R'
   , 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
   , '2', '3', '4', '5', '6', '7', '8', '9'
};

#define ASSERT_POWER_OF_2(n) assert(~((n) - 1) % (n) == 0)
#define ALPHABET_MOD(x) ((x) & (1 << ALPHABET_BITS) - 1)

int main(int argc, char **argv) {
   char const *error= 0;
   int a= 0;
   ARCFOUR_VARDEFS(static);
   /* Ensure SBOX_SIZE is an integral power of 2. */
   ASSERT_POWER_OF_2(SBOX_SIZE);
   /* Ensure correct alphabet size. */
   assert(DIM(alphabet) == 1 << ALPHABET_BITS);
   {
      int optpos= 0;
      if (getopt_simplest(&a, &optpos, argc, argv)) {
         error= "Unsupported option!"; goto fail;
      }
   }
   for (;;) {
      if (a < argc) {
         if (!freopen(argv[a], "rb", stdin)) {
            (void)fputs("Could not open", stderr);
            add_arg:
            (void)fputs(" \"", stderr);
            (void)fputs(argv[a], stderr);
            error= "\"!"; goto fail;
         }
      }
      /* Hash current standard input */
      ARCFOUR_STEP_1;
      ARCFOUR_STEP_2;
      /* Process input as an (overly long) key to set. */
      {
         int c;
         while ((c= getchar()) != EOF) {
            ARCFOUR_STEP_3;
            assert(c >= 0); assert(c < SBOX_SIZE);
            ARCFOUR_STEP_4_SETUP((unsigned)c);
            ARCFOUR_STEP_5_DROP;
         }
      }
      if (ferror(stdin)) {
         if (a < argc) {
            (void)fputs("Error reading", stderr);
            goto add_arg;
         }
         error= "Read error!"; goto fail;
      }
      assert(feof(stdin));
      /* Finish key setup. */
      ARCFOUR_STEP_2;
      /* Drop the initial pseudorandom output. */
      {
         unsigned k;
         for (k= DROP_N; k--; ) {
            ARCFOUR_STEP_3;
            ARCFOUR_STEP_4;
            ARCFOUR_STEP_5_DROP;
         }
      }
      /* Produce the message digest. */
      {
         int k;
         unsigned buf, bufbits= 0;
         #ifndef NDEBUG
            buf= 0;
         #endif
         assert(DIGEST_BITS % 8 == 0);
         for (k= DIGEST_BITS; k > 0; k-= ALPHABET_BITS) {
            if (bufbits < ALPHABET_BITS) {
               /* Append the bits of another ARCFOUR output octet to <buf>. */
               ARCFOUR_STEP_3;
               ARCFOUR_STEP_4;
               ARCFOUR_STEP_5;
               buf= buf << 8 | ARCFOUR_STEP_6();
               bufbits+= 8;
            }
            assert(bufbits >= ALPHABET_BITS);
            {
               int c= alphabet[ALPHABET_MOD(buf >> bufbits - ALPHABET_BITS)];
               bufbits-= ALPHABET_BITS;
               if (putchar(c) != c) goto wrerr;
            }
         }
         if (a < argc) {
            if (putchar(' ') == EOF) goto wrerr;
            if (fputs(argv[a], stdout) < 0) goto wrerr;
         }
         if (putchar('\n') == EOF) goto wrerr;
      }
      if (!(++a < argc)) break;
   }
   if (fflush(0)) {
      wrerr: error= "Write error!";
      fail:
      (void)fputs(error, stderr);
      (void)fputc('\n', stderr);
   }
   return error ? EXIT_FAILURE : EXIT_SUCCESS;
}
