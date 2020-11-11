/*
 * mdarc4 - abuse ARC4 as a simplistic and reasonably fast hash algorithm
 *
 * Version 2020.316.1
 *
 * Copyright (c) 2020 Guenther Brunthaler. All rights reserved.
 *
 * This source file is free software.
 * Distribution is permitted under the terms of the GPLv3.
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#define SBOX_SIZE (1 << 8)

#define SCAN_DEFAULT (3 * SBOX_SIZE)
#define DROP_N (4 * SCAN_DEFAULT)

#define ALPHABET_BITS 5
#define DIGEST_BITS 256

static char const alphabet[]= {
   /*
   $ cat << 'EOF' | perl
   print join(", ", map "'$_'", grep /[^01OI]/, ("A".."Z", "0".."9")), "\n"
   EOF
   */
     'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'
   , 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R'
   , 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
   , '2', '3', '4', '5', '6', '7', '8', '9'
};

#define DIM(array) (sizeof(array) / sizeof *(array))
#define ASSERT_POWER_OF_2(n) assert(~((n) - 1) % (n) == 0)

#define ARC4_MOD(x) ((x) & SBOX_SIZE - 1)
#define ARC4_STEP_1 for (i= SBOX_SIZE; i-- ;) s[i]= (unsigned char)i;
#define ARC4_STEP_2 i= j= 0
#define ARC4_STEP_3 i= ARC4_MOD(i + 1)
#define ARC4_STEP_4_SETUP(keyoctet) j= ARC4_MOD(j + s[i] + keyoctet)
#define ARC4_STEP_4 j= ARC4_MOD(j + s[i])
#define ARC4_STEP_5_DROP v1= s[i]; s[i]= s[j]; s[j]= v1
#define ARC4_STEP_5 v1= s[i]; s[i]= v2= s[j]; s[j]= v1
#define ARC4_STEP_6() s[ARC4_MOD(v1 + v2)]

int main(void) {
   static unsigned char s[SBOX_SIZE];
   char const *error= 0;
   unsigned i, j;
   unsigned char v1, v2;
   /* Ensure SBOX_SIZE is an integral power of 2. */
   ASSERT_POWER_OF_2(SBOX_SIZE);
   /* Ensure correct alphabet size. */
   assert(DIM(alphabet) == 1 << ALPHABET_BITS);
   ARC4_STEP_1;
   ARC4_STEP_2;
   /* Process input as an (overly long) key to set. */
   {
      int c;
      while ((c= getchar()) != EOF) {
         ARC4_STEP_3;
         assert(c >= 0); assert(c < SBOX_SIZE);
         ARC4_STEP_4_SETUP((unsigned)c);
         ARC4_STEP_5_DROP;
      }
   }
   if (ferror(stdin)) { error= "Read error!"; goto fail; }
   assert(feof(stdin));
   /* Finish key setup. */
   ARC4_STEP_2;
   /* Drop the initial keystream. */
   {
      unsigned k;
      for (k= DROP_N; k--; ) {
         ARC4_STEP_3;
         ARC4_STEP_4;
         ARC4_STEP_5_DROP;
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
            ARC4_STEP_3;
            ARC4_STEP_4;
            ARC4_STEP_5;
            buf= buf << 8 | ARC4_STEP_6();
            bufbits+= 8;
         }
         assert(bufbits >= ALPHABET_BITS);
         {
            int c= alphabet[
                  buf >> bufbits - ALPHABET_BITS
               &  (1 << ALPHABET_BITS) - 1
            ];
            bufbits-= ALPHABET_BITS;
            if (putchar(c) != c) goto wrerr;
         }
      }
      if (putchar('\n') != '\n') goto wrerr;
   }
   if (fflush(0)) {
      wrerr: error= "Write error!";
      fail:
      (void)fputs(error, stderr);
      (void)fputc('\n', stderr);
   }
   return error ? EXIT_FAILURE : EXIT_SUCCESS;
}
