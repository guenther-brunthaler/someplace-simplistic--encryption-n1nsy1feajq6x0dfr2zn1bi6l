#define VERSTR_1 "Version 2020.355"
#define VERSTR_2 "Copyright (c) 2020 Guenther Brunthaler."

static char help[]= { /* Formatted as 66 output columns. */
   "rc4dropN - ARCFOUR-drop<N> encryption/decryption\n"
   "\n"
   "The program encrypts binary data plaintext or decrypts binary\n"
   "data ciphertext and writes the binary result to standard output.\n"
   "Note that actual text data is a subset of binary data and will\n"
   "therefore also work as plaintext. Encryption and decryption are\n"
   "the same operation when using the ARCFOUR-drop<N> algorithm, so\n"
   "it depends on the input what actually happens.\n"
   "\n"
   "This program has no command line arguments. It reads everything\n"
   "required from it standard input in the following format:\n"
   "\n"
   "N<drops>Z<key_size>K<key>T<data>\n"
   "\n"
   "where\n"
   "\n"
   "N, Z, K, T: Those literal characters stored as ASCII octets\n"
   "octet: A binary 8-bit byte\n"
   "<drops>: The value (<N> / 256) stored as one octet\n"
   "<key_size>: The size (0 means 256) of <key> stored as one octet\n"
   "<key>: The encryption key with octet count given by <key_size>\n"
   "<data>: arbitrary number of plaintext or ciphertext octets\n"
   "\n"
   "<N> is a parameter of the algorithm. It specifies the initial\n"
   "number of generated pseudorandom bytes which will be thrown away\n"
   "and not be used for actual encryption/decryption. This hardens\n"
   "the algorithm against several known attacks.\n"
   "\n"
   "ARCFOUR-drop768 is a frequent choice, but ARCFOUR-drop3072 is\n"
   "recommended as a more conservative and even safer choice.\n"
   "ARCFOUR-drop0 is identical to the original ARCFOUR algorithm.\n"
   "\n"
   "All key sizes from 1 through 256 octets are supported. However,\n"
   "the internal state of ARCFOUR can only represent 256! different\n"
   "keys, and a key made of 211 random octets is enough to provide\n"
   "this information. Longer random keys will therefore not provide\n"
   "more security than this.\n"
   "\n"
   "Note that the same key must *never* be reused for different\n"
   "messages! Hash some password and a nonce (salt) to derive the\n"
   "actual key.\n"
   "\n"
   "Recommended: Sandwich the password (without any terminating\n"
   "newline) between two copies of a 32-octet random salt for key\n"
   "derivation and hash the whole thing with 'rc4hash -rb 211'. Put\n"
   "another copy of the salt as the first 32 octets of the\n"
   "encrypted file, allowing the salt to be retrieved from there for\n"
   "later decryption.\n"
   "\n"
   VERSTR_1 "\n"
   "\n"
   VERSTR_2 " All rights reserved.\n"
   "\n"
   "This program is free software.\n"
   "Distribution is permitted under the terms of the GPLv3."
};

#include "arc4_common.h"
#include <dim_sdbrke8ae851uitgzm4nv3ea2.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#define ASSERT_POWER_OF_2(n) assert(~((n) - 1) % (n) == 0)

int main(int argc, char **argv) {
   char const *error= 0;
   ARCFOUR_VARDEFS(static);
   unsigned drops, key_size;
   /* Ensure SBOX_SIZE is an integral power of 2. */
   ASSERT_POWER_OF_2(SBOX_SIZE);
   if (argc > 1) { usage: error= help; goto fail; }
   (void)argv;
   if (getchar() != 'N') goto usage;
   {
      int c;
      if ((c= getchar()) == EOF) goto usage;
      drops= (unsigned)c << 8;
   }
   if (getchar() != 'Z') goto usage;
   {
      int c;
      if ((c= getchar()) == EOF) goto usage;
      key_size= c ? (unsigned)c : 256;
   }
   if (getchar() != 'K') goto usage;
   /* Prepare key setup. */
   ARCFOUR_STEP_1_KEY;
   ARCFOUR_STEP_2;
   /* Process the fixed-size key. */
   {
      unsigned k;
      for (i= k= 0; i < SBOX_SIZE; ++i) {
         static unsigned char recycle[SBOX_SIZE >> 1];
         int c;
         if (i >= key_size) {
            assert(k == i % key_size);
            assert(k < DIM(recycle));
            c= recycle[k];
         } else {
            if ((c= getchar()) == EOF) goto usage;
            assert(c >= 0); assert(c < SBOX_SIZE);
            assert(i == k);
            if (i < (unsigned)DIM(recycle)) recycle[i]= (unsigned char)c;
         }
         if (++k == key_size) k= 0;
         assert(c >= 0); assert(c < SBOX_SIZE);
         ARCFOUR_STEP_4_KEY((unsigned)c);
         ARCFOUR_STEP_5_DROP;
         ARCFOUR_STEP_7_KEY;
      }
   }
   /* Finish key setup. */
   ARCFOUR_STEP_2;
   /* Drop the initial pseudorandom output. */
   while (drops--) {
      ARCFOUR_STEP_3_PRNG; ARCFOUR_STEP_4_PRNG; ARCFOUR_STEP_5_DROP;
   }
   if (getchar() != 'T') goto usage;
   /* Encrypt or decrypt standard input to standard output. */
   {
      int c;
      while ((c= getchar()) != EOF) {
         ARCFOUR_STEP_3_PRNG; ARCFOUR_STEP_4_PRNG; ARCFOUR_STEP_5_PRNG;
         assert(c >= 0); assert(c < SBOX_SIZE);
         c^= ARCFOUR_STEP_6_PRNG();
         if (putchar(c) != c) goto wrerr;
      }
   }
   if (ferror(stdin)) { error= "Read error!"; goto fail; }
   assert(feof(stdin));
   if (fflush(0)) {
      wrerr: error= "Write error!";
      fail:
      (void)fputs(error, stderr);
      (void)fputc('\n', stderr);
   }
   return error ? EXIT_FAILURE : EXIT_SUCCESS;
}
