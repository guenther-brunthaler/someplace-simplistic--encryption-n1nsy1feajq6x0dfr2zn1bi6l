#define VERSTR_1 "Version 2020.355"
#define VERSTR_2 "Copyright (c) 2020 Guenther Brunthaler."

static char help[]= { /* Formatted as 66 output columns. */
   "rc4sxs-crypt - modified ARCFOUR using SUBTRACT-XOR-SUBTRACT\n"
   "instead of just XOR\n"
   "\n"
   "Usage: rc4sxs-crypt <options> [ -- ] <one_time_key>\n"
   "\n"
   "The binary octet data (octets are 8-bit bytes) to be encrypted or\n"
   "decrypted will be read from standard input and the binary result\n"
   "will be written to standard output.\n"
   "\n"
   "<one_time_key> is the pathname of a file containing the binary\n"
   "key. This key must only be used for encrypting one specific\n"
   "message. It must not be reused for encrypting a different message.\n"
   "\n"
   "Although keys of any size are supported, the keys cannot become\n"
   "more secure than 212 full-entropy random octets (such as taken\n"
   "from from '/dev/random').\n"
   "\n"
   "Note that special files like '/dev/fd/9' will also be accepted as\n"
   "<one_time_key>, so you can also feed the key to the program via\n"
   "any redirected file descriptor.\n"
   "\n"
   "Supported options:\n"
   "\n"
   "-e: Selects encryption mode\n"
   "-d: Selects decryption mode\n"
   "-h: Display this help and exit\n"
   "-V: Display version information and exit\n"
   "\n"
   "This program uses ARCFOUR-drop3072 as a CSPRNG (cryptographically\n"
   "secure pseudo-random generator) and takes the next three octets\n"
   "(R0, R1 and R2) of its pseudo-random stream in order to\n"
   "encrypt/decrypt the next plaintext/ciphertext octet P/C as\n"
   "follows:\n"
   "\n"
   "C = ((P - R2) ^ R1) - R0\n"
   "\n"
   "P = ((C + R0) ^ R1) + R2\n"
   "\n"
   "where '^' is the bitwise XOR-operation, '+' is addition modulo\n"
   "256, and '-' is subtraction modulo 256.\n"
   "\n"
   "ARCFOUR-drop3072 is the same as original ARCFOUR except that the\n"
   "first 3072 output octets are thrown away and not used for actual\n"
   "encryption/decryption. This protects against some known attacks.\n"
   "\n"
   "This program also uses a modification of the original ARCFOUR key\n"
   "schedule which actually makes it simpler: All octets of the key\n"
   "are processed exactly once. No attempt is made to recycle shorter\n"
   "keys than 256 octets, nor will key octets beyond the 256th be\n"
   "ignored.\n"
   "\n"
   "Note this program can also used for hashing: Use the data to be\n"
   "hashed as the binary key and encrypt a string of binary zero\n"
   "octets (such as drawn from '/dev/zero') with the size of the\n"
   "desired hash digest. The encrypted output will be the binary hash.\n"
   "\n"
   "The program can also derive one-time keys for encryption and MAC\n"
   "of a specific message from a long-term binary key and a binary\n"
   "salt: Concatenate a 106-octet pre-salt with the long-term key and\n"
   "a 106-octet post-salt and hash the result into 424 octets: A 212\n"
   "octet one-time encryption key and a 212 octet one-time MAC key.\n"
   "\n"
   "You can derive a long-term binary key from a long-term password by\n"
   "stripping any newline character from it and and convert it into\n"
   "UTF-8, NFKC (normalization form compatibility composition). The\n"
   "utilities 'idn' and 'uconv' can convert into NFKC. If the\n"
   "passwords are restricted to ASCII no such normalization will be\n"
   "necessary as it will make no difference then.\n"
   "\n"
   "The program can also be used for salt stretching: Hash a shorter\n"
   "salt (say 32 octets) into as much salt octets of hash output as\n"
   "there are required (say 106 + 106 = 212 octets).\n"
   "\n"
   "It is also possible to create a MAC (message authentication code):\n"
   "Hash the message to be integrity-protected into a 32-octet message\n"
   "digest. Then encrypt that with the MAC key.\n"
   "\n"
   "If a salt is used for encryption, it is recommended to prepend a\n"
   "32-octet salt before the encrypted message.\n"
   "\n"
   "If a MAC is used to integrity-protect a message, it is recommended\n"
   "to append a 32-octet MAC after the encrypted data.\n"
   "\n"
   "If a message shall be both encrypted and MAC-protected, it is\n"
   "recommended to calculate the MAC over the already-encrypted\n"
   "message ('encrypt-then-MAC').\n"
   "\n"
   "A salt can be created by hashing the concatenation of a message\n"
   "counter and an account hash into 32 octets of salt. Alternatively,\n"
   "the output of 'LC_ALL=C date -u' can be used instead of a counter.\n"
   "\n"
   "The account hash is a 32 octet hash which should include at least\n"
   "the following information: Fully-qualified host name, login name,\n"
   "UTC date/time of hash creation. You can add additional info also,\n"
   "such as the output of 'ps -Alf' and 'df'. This hash needs only be\n"
   "calculated once per account.\n"
   "\n"
};

static char version_info[]= {
   VERSTR_1 "\n"
   "\n"
   VERSTR_2 " All rights reserved.\n"
   "\n"
   "This program is free software.\n"
   "Distribution is permitted under the terms of the GPLv3."
};

#include "arc4_common.h"
#include <dim_sdbrke8ae851uitgzm4nv3ea2.h>
#include <getopt_nh7lll77vb62ycgwzwf30zlln.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#define ADD_MOD256(v, inc) ((v)= (v) + (inc) & 256 - 1)
#define SUB_MOD256(v, dec) ADD_MOD256(v, 256 - (dec))
#define ASSERT_MOD256(c) assert((c) >= 0); assert((c) < 256)
#define CSPRNG_GET(out) \
   ARCFOUR_STEP_3_PRNG; ARCFOUR_STEP_4_PRNG; ARCFOUR_STEP_5_PRNG; \
   out= ARCFOUR_STEP_6_PRNG()

int main(int argc, char **argv) {
   char const *error= 0, *current_file;
   int a= 0, encrypt= -1;
   FILE *key;
   ARCFOUR_VARDEFS(static);
   {
      int optpos= 0;
      for (;;) {
         int opt;
         switch (opt= getopt_simplest(&a, &optpos, argc, argv)) {
            case 0: goto no_more_options;
            case 'e': if (!(encrypt < 0)) goto usage; encrypt= 1; break;
            case 'd': if (!(encrypt < 0)) goto usage; encrypt= 0; break;
            case 'h':
               if (fputs(help, stdout) < 0) goto wrerr;
               /* Fall through. */
            case 'V':
               if (puts(version_info) < 0) goto wrerr;
               goto cleanup;
            default: getopt_simplest_perror_opt(opt); error= ""; goto leave;
         }
      }
   }
   no_more_options:
   if (encrypt < 0) { error= "Please specify -e or -d!"; goto fail; }
   if (a + 1 != argc) {
      usage:
      (void)fputs(help, stderr);
      error= version_info; goto fail;
   }
   if (!(key= fopen(current_file= argv[a], "rb"))) {
      (void)fputs("Could not open key file", stderr);
      add_arg:
      (void)fputc(' ', stderr);
      if (current_file) {
         (void)fputc('"', stderr);
         (void)fputs(current_file, stderr);
         (void)fputc('"', stderr);
      } else {
         (void)fputs("standard input", stderr);
      }
      error= "!";
      goto fail;
   }
   {
      #ifdef TESTVECTORS_PEMTFGYBNQJY1ZYR6J7I0HNUH
      static char recycle[SBOX_SIZE << 1];
      int klen= 0;
      #endif
      ARCFOUR_STEP_1_KEY; ARCFOUR_STEP_2;
      {
         int c;
         while ((c= getc(key)) != EOF) {
            ASSERT_MOD256(c);
            #ifdef TESTVECTORS_PEMTFGYBNQJY1ZYR6J7I0HNUH
            if (klen >= SBOX_SIZE) { assert(klen == SBOX_SIZE); break; }
            if (klen < (int)DIM(recycle)) recycle[klen]= (char)c;
            ++klen;
            #endif
            ARCFOUR_STEP_4_KEY((unsigned)c);
            ARCFOUR_STEP_5_DROP; ARCFOUR_STEP_7_KEY;
         }
      }
      #ifdef TESTVECTORS_PEMTFGYBNQJY1ZYR6J7I0HNUH
      {
         int ri= 0, left;
         for (left= SBOX_SIZE - klen; left--; ) {
            assert(ri < (int)DIM(recycle));
            ARCFOUR_STEP_4_KEY((unsigned)recycle[ri]);
            ARCFOUR_STEP_5_DROP; ARCFOUR_STEP_7_KEY;
            if (++ri >= klen) { assert(ri == klen); ri= 0; }
         }
      }
      #endif
   }
   if (ferror(key)) {
      (void)fclose(key);
      rderr:
      (void)fputs("Error reading from", stderr);
      goto add_arg;
   }
   assert(feof(key));
   if (fclose(key)) { error= "Error closing"; goto add_arg; }
   current_file= 0;
   ARCFOUR_STEP_2;
   {
      unsigned drop;
      for (drop= DROP_N; drop--; ) {
         #ifndef TESTVECTORS_PEMTFGYBNQJY1ZYR6J7I0HNUH
         ARCFOUR_STEP_3_PRNG; ARCFOUR_STEP_4_PRNG; ARCFOUR_STEP_5_DROP;
         #endif
      }
   }
   switch (encrypt) {
      int out;
      case 1: /* Encryption. */
         while ((out= getchar()) != EOF) {
            int r0, r1, r2;
            ASSERT_MOD256(out);
            CSPRNG_GET(r0);
            CSPRNG_GET(r1);
            CSPRNG_GET(r2);
            SUB_MOD256(out, r2);
            out^= r1;
            SUB_MOD256(out, r0);
            if (putchar(out) != out) goto wrerr;
         }
         break;
      case 0: /* Decryption. */
         while ((out= getchar()) != EOF) {
            int r;
            ASSERT_MOD256(out);
            #ifndef TESTVECTORS_PEMTFGYBNQJY1ZYR6J7I0HNUH
            CSPRNG_GET(r);
            ADD_MOD256(out, r);
            #endif
            CSPRNG_GET(r);
            out^= r;
            #ifndef TESTVECTORS_PEMTFGYBNQJY1ZYR6J7I0HNUH
            CSPRNG_GET(r);
            ADD_MOD256(out, r);
            #endif
            if (putchar(out) != out) goto wrerr;
         }
         break;
      default: goto usage;
   }
   if (ferror(stdin)) goto rderr;
   assert(feof(stdin));
   cleanup:
   if (fflush(0)) {
      wrerr: error= "Error writing to standard output!";
      fail:
      (void)fputs(error, stderr);
      (void)fputc('\n', stderr);
   }
   leave:
   return error ? EXIT_FAILURE : EXIT_SUCCESS;
}
