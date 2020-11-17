/*
 * rc4sxs - modified ARCFOUR using SUBTRACT-XOR-SUBTRACT instead of just XOR
 *
 * Uses ARCFOUR-drop3072 as a CSPRNG and uses the next three octets of the
 * pseudorandom stream R[0], R[1] and R[2] in order to encrypt/decrypt the
 * next data octet as follows:
 *
 * C[n]= ((P[n] xor R2[n]) - R1[n]) xor R0[n]
 * P[n]= ((P[n] xor R0[n]) + R1[n]) xor R2[n]
 *
 * Another difference is a modification to the ARCFOUR key schedule which
 * actually makes it simpler: All octets of the key are processed exactly
 * once. No attempt is made to recycle shorter keys than 256 octets, or to
 * ignore any key octets beyond the 256th.
 *
 * Version 2020.322
 *
 * Copyright (c) 2020 Guenther Brunthaler. All rights reserved.
 *
 * This source file is free software.
 * Distribution is permitted under the terms of the GPLv3.
 */

#include "arc4_common.h"
#include <getopt_nh7lll77vb62ycgwzwf30zlln.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#define ASSERT_POWER_OF_2(n) assert(~((n) - 1) % (n) == 0)

int main(int argc, char **argv) {
   char const *error= 0;
   int encrypt= -1, a= 0;
   ARCFOUR_VARDEFS(static);
   /* Ensure SBOX_SIZE is an integral power of 2. */
   ASSERT_POWER_OF_2(SBOX_SIZE);
   {
      int cpos= 0;
      for (;;) {
         switch (getopt_simplest(&a, &cpos, argc, argv)) {
            case 0: goto no_more_options;
            case 'e': encrypt= 1; break;
            case 'd': encrypt= 0; break;
            default: error= "Unsupported option!"; goto fail;
         }
      }
   }
   no_more_options:
   if (encrypt < 0) { error= "Please specify -e or -d!"; goto fail; }
   if (a + 1 != argc) {
      error=
         "The pathname of the key file must be the only non-option argument!"
      ;
      goto fail;
   }
   {
      FILE *keyfile;
      if (!(keyfile= fopen(argv[a], "rb"))) {
         error= "Cannot open specified keyfile!"; goto fail;
      }
      /* Prepare key setup. */
      ARCFOUR_STEP_1;
      ARCFOUR_STEP_2;
      /* Process an (arbitrarily long) key. */
      {
         int c;
         while ((c= getc(keyfile)) != EOF) {
            ARCFOUR_STEP_3;
            assert(c >= 0); assert(c < SBOX_SIZE);
            ARCFOUR_STEP_4_SETUP((unsigned)c);
            ARCFOUR_STEP_5_DROP;
         }
      }
      if (ferror(keyfile)) {
         (void)fclose(keyfile);
         rderr: error= "Read error!"; goto fail;
      }
      assert(feof(keyfile));
      if (fclose(keyfile)) { error= "Error closing key file."; goto fail; }
   }
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
   if (encrypt) {
      /* Encrypt stdandard input to standard output. */
      int c, r0, r1;
      while ((c= getchar()) != EOF) {
         ARCFOUR_STEP_3; ARCFOUR_STEP_4; ARCFOUR_STEP_5;
         r0= ARCFOUR_STEP_6();
         ARCFOUR_STEP_3; ARCFOUR_STEP_4; ARCFOUR_STEP_5;
         r1= ARCFOUR_STEP_6();
         ARCFOUR_STEP_3; ARCFOUR_STEP_4; ARCFOUR_STEP_5;
         assert(c >= 0); assert(c < SBOX_SIZE);
         c= SBOX_MOD(c ^ ARCFOUR_STEP_6() - r1) ^ r0;
         if (putchar(c) != c) goto wrerr;
      }
   } else {
      /* Decrypt stdandard input to standard output. */
      int c;
      while ((c= getchar()) != EOF) {
         ARCFOUR_STEP_3; ARCFOUR_STEP_4; ARCFOUR_STEP_5;
         assert(c >= 0); assert(c < SBOX_SIZE);
         c^= ARCFOUR_STEP_6();
         ARCFOUR_STEP_3; ARCFOUR_STEP_4; ARCFOUR_STEP_5;
         c= SBOX_MOD(c + ARCFOUR_STEP_6());
         ARCFOUR_STEP_3; ARCFOUR_STEP_4; ARCFOUR_STEP_5;
         c^= ARCFOUR_STEP_6();
         if (putchar(c) != c) goto wrerr;
      }
   }
   if (ferror(stdin)) goto rderr;
   assert(feof(stdin));
   if (fflush(0)) {
      wrerr: error= "Write error!";
      fail:
      (void)fputs(error, stderr);
      (void)fputc('\n', stderr);
   }
   return error ? EXIT_FAILURE : EXIT_SUCCESS;
}
