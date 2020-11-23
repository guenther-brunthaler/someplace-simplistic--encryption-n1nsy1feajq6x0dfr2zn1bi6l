#define VERSTR_1 "Version 2020.328.2"
#define VERSTR_2 "Copyright (c) 2020 Guenther Brunthaler."

static char help[]= { /* Formatted as 66 output columns. */
   "treyfer-ofb - treyfer-ofb stream cipher encryption/decryption\n"
   "\n"
   "The program encrypts binary data plaintext or decrypts binary\n"
   "data ciphertext and writes the binary result to standard output.\n"
   "Note that actual text data is a subset of binary data and will\n"
   "therefore also work as plaintext. Encryption and decryption are\n"
   "the same operation when using the treyfer-ofb algorithm, so it\n"
   "depends on the input what actually happens.\n"
   "\n"
   "This program has no command line arguments. It reads everything\n"
   "required from its standard input in the following format:\n"
   "\n"
   "K<key8>I<iv8>T<data>\n"
   "\n"
   "where\n"
   "\n"
   "<key8>: 8 octets (binary 8-bit data bytes) encryption key\n"
   "<iv8>: 8 octets initialization vector (IV)\n"
   "<data>: arbitrary number of plaintext or ciphertext octets\n"
   "\n"
   "IMPORTANT: This cipher is insecure when used on its own!\n"
   "\n"
   "It is only supposed to be used as a secondary encryption in order\n"
   "to strengthen some other cipher against known attacks.\n"
   "\n"
   "The short key size of 64 bit makes treyfer-ofb an insecure\n"
   "algorithm when used on its own. It is rather slow (about eight\n"
   "times slower than ARCFOUR). There is also a known attack against\n"
   "this cipher which can crack it using 2^32 known plaintexts with\n"
   "an effort of 2^44. The only real advantage of this cipher is its\n"
   "simplicity, making it very hard to imagine how someone might have\n"
   "mangaged to plant an algorithmic backdoor into its design.\n"
   "\n"
   "treyfer-ofb can be particularly useful for strengthening\n"
   "ARCFOUR-drop3072 against known attacks.\n"
   "\n"
   "It is therefore recommended to use both ciphers in a cascade (the\n"
   "order of application does not matter since it will yield the same\n"
   "results) whenever data with recognizable structure (i. e.\n"
   "anything other than binary random data like random keys or\n"
   "already well-encrypted data) shall be encrypted.\n"
   "\n"
   "When used on their own, ARCFOUR-drop3072 may have a few\n"
   "weaknesses and treyfer-ofb is weak, but when used together no\n"
   "attacks are known (as of 2020) against the combination and it can\n"
   "most likely be considered to be very strong encryption.\n"
   "\n"
   "ALSO IMPORTANT: The same combination of key and IV must *never*\n"
   "be reused for different messages when using treyfer-ofb! Hash\n"
   "some password and a nonce (unique salt) in order to derive the\n"
   "actual key.\n"
   "\n"
   "It might be best to derive the IV in the same way, too, although\n"
   "it could also be a counter that never repeats for the same key\n"
   "and does not even necessarily be kept secret.\n"
   "\n"
   "Recommended: Sandwich the password (without any terminating\n"
   "newline) between two copies of a 32-octet random salt for key\n"
   "derivation and hash the whole thing with 'rc4hash -rb 8'. Put\n"
   "another copy of the salt as the first 32 octets into the\n"
   "encrypted file, allowing the salt to be retrieved from there for\n"
   "decryption.\n"
   "\n"
   "All ciphers of the treyfer family require an unspecified s-box\n"
   "that is used to personalize its algorithm.\n"
   "\n"
   "This implementation uses the rc4hash utility for hashing the\n"
   "ASCII string 'treyfer-ofb sbox' into 256 output octets in order\n"
   "to create a fixed s-box. It starts with an\n"
   "identity-transformation (i. e. no-op) s-box and then reads the\n"
   "256 octets provided by rc4hash, which are interpreted as s-box\n"
   "indices for which to swap elements with the one at the current\n"
   "(ascending) loop index.\n"
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
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#define IS_POWER_OF_2(n) (~((n) - 1) % (n) == 0)

int main(int argc, char **argv) {
   char const *error= 0;
   static unsigned char const sbox[1 << CHAR_BIT]= {
      #include "treyfer_sbox.h"
   };
   unsigned char key[8], block[8];
   if (argc > 1) { usage: error= help; goto fail; }
   (void)argv;
   if (getchar() != 'K') goto usage;
   /* Read key. No special key setup is required by the algorithm. */
   {
      unsigned n;
      for (n= 0; n < (unsigned)DIM(key); ++n) {
         int c;
         if ((c= getchar()) == EOF) goto usage;
         assert(c >= 0); assert(c <= UCHAR_MAX);
         key[n]= (unsigned char)c;
      }
   }
   if (getchar() != 'I') goto usage;
   /* Read IV. Use as the initial block contents for OFB mode. */
   {
      unsigned n;
      for (n= 0; n < (unsigned)DIM(block); ++n) {
         int c;
         if ((c= getchar()) == EOF) goto usage;
         assert(c >= 0); assert(c <= UCHAR_MAX);
         block[n]= (unsigned char)c;
      }
   }
   if (getchar() != 'T') goto usage;
   /* Encrypt or decrypt standard input to standard output. */
   {
      int c;
      unsigned o= 0;
      assert(IS_POWER_OF_2(DIM(key)));
      assert(IS_POWER_OF_2(DIM(block)));
      assert(IS_POWER_OF_2(CHAR_BIT));
      while ((c= getchar()) != EOF) {
         #define MOD(x, m) ((unsigned char)(x) & (unsigned char)((m) - 1))
         #define MOD_A(x, array) MOD(x, DIM(array))
         if (o == 0) {
            #define NUMROUNDS 32
            unsigned i;
            unsigned char t= block[0];
            for (i= 0; i < CHAR_BIT * NUMROUNDS; ++i) {
               t+= key[MOD_A(i, key)];
               t= MOD_A(sbox[t] + block[MOD_A(i + 1, block)], sbox);
               /* ROT-L by 1 bit. */
               block[MOD_A(i + 1, block)]= t= t << 1 | t >> CHAR_BIT - 1;
            }
         }
         assert(c >= 0); assert(c <= UCHAR_MAX);
         c^= block[o];
         o= MOD_A(o + 1, block);
         if (putchar(c) != c) goto wrerr;
         #undef MOD_A
         #undef MOD
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
