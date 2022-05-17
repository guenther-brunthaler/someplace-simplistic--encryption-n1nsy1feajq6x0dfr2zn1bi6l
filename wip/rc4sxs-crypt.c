#define VERSTR_1 "Version 2021.326"
#define VERSTR_2 "Copyright (c) 2020-2021 Guenther Brunthaler."

static char help[]= { /* Formatted as 66 output columns. */
   "rc4sxs-crypt - modified ARCFOUR using SUBTRACT-XOR-SUBTRACT\n"
   "instead of just XOR\n"
   "\n"
   "Usage: rc4sxs-crypt <options>\n"
   "\n"
   "The binary octet data (octets are 8-bit bytes) to be encrypted or\n"
   "decrypted will be read from standard input and the binary result\n"
   "will be written to standard output.\n"
   "\n"
   "\n"
   "Supported options:\n"
   "\n"
   "-E <one_time_key>: Selects raw encryption mode. Minimally slower\n"
   "than decryption. <one_time_key> is the pathname of a file\n"
   "containing the binary encryption key. This key must only be used\n"
   "for encrypting one specific message. It must not be reused for\n"
   "encrypting a different message.\n"
   "\n"
   "-D <one_time_key>: Selects raw decryption mode. Also recommended\n"
   "for hashing. See the explanation for -E about <one_time_key>,\n"
   "except that it is used for decryption in this mode.\n"
   "\n"
   "-M <one_time_mac_key>: Create or verify a MAC, using the specified\n"
   "pathname for obtaining the binary MAC key. This key (of arbitrary\n"
   "size, but 211 octets are recommended) will be prepended to the\n"
   "encrypted data, and the concatenated result will be hashed\n"
   "yielding a 32-octet MAC. In encryption mode this MAC will be\n"
   "appended after the end of the encrypted data; in decryption mode\n"
   "it will be verified (an error will be raised if the calculated MAC\n"
   "does not match the stored MAC). The hashing itself will use a\n"
   "separate instance of the decryption algorithm, independent from\n"
   "the instance of the main operation mode (-D or -E).\n"
   "\n"
   "-h: Display this help and exit\n"
   "-V: Display version information and exit\n"
   "\n"
   "For all options which take the pathname of a key file as an\n"
   "argument, special files like '/dev/fd/9' are also eligible. This\n"
   "allows to read the binary keys or the data to be hashed from\n"
   "redirected file descriptors rather than from real files.\n"
   "\n"
   "Although keys of any size are supported and every octet of a key\n"
   "will have an effect on the encryption, even the longest keys will\n"
   "not be more secure than 211-octet (1684 bit) full-entropy random\n"
   "binary keys (such as taken from from '/dev/random').\n"
   "\n"
   "This program uses ARCFOUR-drop3072 as a CSPRNG (cryptographically\n"
   "secure pseudo-random number generator) and takes the next three\n"
   "octets R0, R1 and R2) of its pseudo-random output stream in order\n"
   "to aw encrypt/decrypt the next plaintext/ciphertext octet P/C as\n"
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
   "hashed as the binary key and encrypt or decrypt some constant\n"
   "octet string with it. The resulting octet string is then the hash\n"
   "value. This program decrypts minimally faster than it can encrypt,\n"
   "therefore it is recommended to always use decryption for hashing.\n"
   "The size of the constant octet string will be the same as the hash\n"
   "output size. For simplicity, it is recommended to use binary zero\n"
   "octets as the constant string to be decrypted. In particular,\n"
   "'/dev/zero' can be used to obtain such zero octets via 'dd'.\n"
   "\n"
   "The program can also derive one-time keys for both data encryption\n"
   "and MAC calculation of some specific message from a long-term\n"
   "binary key and a binary per-message salt: Concatenate a 106-octet\n"
   "pre-salt with the long-term key and a 106-octet post-salt and hash\n"
   "the result into 424 octets: A 212 octet one-time encryption key\n"
   "and a 212 octet one-time MAC key.\n"
   "\n"
   "You can derive a long-term binary key from a long-term password by\n"
   "stripping any newline character from it and and converting it into\n"
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
   "Prepend a 32-octet MAC key before the message to be authenticated,\n"
   "and hash the concatenated result. The hash digest then represents\n"
   "the MAC. Similar to the encryption key, the MAC key must not be\n"
   "used to integrity-protect the contents of more than one particular\n"
   "message. It is a one-time key, too. Also, MAC keys must not be\n"
   "re-used as encryption keys. Neither for the same or other\n"
   "messages. Not ever.\n"
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

#include "config.h"
#include "arc4_common.h"
#include <dim_sdbrke8ae851uitgzm4nv3ea2.h>
#include <getopt_nh7lll77vb62ycgwzwf30zlln.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* 256 bit MACs should be safe enough even against quantum computer attacks. */
#define MAC_OCTETS 32

#define ADD_MOD256(v, inc) ((v)= (v) + (inc) & 256 - 1)
#define SUB_MOD256(v, dec) ADD_MOD256(v, 256 - (dec))
#define ASSERT_MOD256(c) assert((c) >= 0); assert((c) < 256)
#define CSPRNG_GET(out) \
   ARCFOUR_STEP_3_PRNG; ARCFOUR_STEP_4_PRNG; ARCFOUR_STEP_5_PRNG; \
   out= ARCFOUR_STEP_6_PRNG()
#define DROP_INITIAL_KEYSTREAM() { \
   unsigned drop; \
   for (drop= DROP_N; drop--; ) { \
      ARCFOUR_STEP_3_PRNG; ARCFOUR_STEP_4_PRNG; ARCFOUR_STEP_5_DROP; \
   } \
}

int main(int argc, char **argv) {
   char const *error= 0, *current_file, *enc_key_fname= 0, *mac_key_fname= 0;
   int encrypt= -1;
   FILE *key;
   #define r4 mac
      ARCFOUR_VARDEFS(static);
   #undef r4
   ARCFOUR_VARDEFS(static);
   static unsigned char iobuf[BUFSIZ + MAC_OCTETS];
   size_t prebuffered= 0;
   {
      int optpos= 0, optind= 0;
      for (;;) {
         int opt;
         switch (opt= getopt_simplest(&optind, &optpos, argc, argv)) {
            case 0:
               if (optind != argc) {
                  error= "Too many arguments!"; goto fail;
               }
               goto no_more_options;
            case 'E':
               if (!(encrypt < 0)) {
                  E_xor_D:
                  error= "-E and -D are mutually exclusive!"; goto fail;
               }
               encrypt= 1;
               goto get_enc_kfile;
            case 'D':
               if (!(encrypt < 0)) goto E_xor_D;
               encrypt= 0;
               get_enc_kfile:
               if (
                  !(
                     enc_key_fname= getopt_simplest_mand_arg(
                        &optind, &optpos, argc, argv
                     )
                  )
               ) {
                  error= "Missing enryption key file pathname!"; goto fail;
               }
               break;
            case 'M':
               if (
                  !(
                     mac_key_fname= getopt_simplest_mand_arg(
                        &optind, &optpos, argc, argv
                     )
                  )
               ) {
                  error= "Missing MAC key file pathname!"; goto fail;
               }
               break;
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
   if (encrypt < 0) {
      error= "Please specify -E or -D!"; goto fail;
   }
   if (!(key= fopen(current_file= enc_key_fname, "rb"))) {
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
      krderr:
      (void)fclose(key);
      rderr:
      (void)fputs("Error reading from", stderr);
      goto add_arg;
   }
   assert(feof(key));
   if (fclose(key)) {
      exotic_error:
      error=
         "An unexpected error has occurred!"
         " This should not normally happen."
      ;
      goto fail;
   }
   ARCFOUR_STEP_2;
   #ifndef TESTVECTORS_PEMTFGYBNQJY1ZYR6J7I0HNUH
      DROP_INITIAL_KEYSTREAM();
   #endif
   if (current_file= mac_key_fname) {
      if (!(key= fopen(current_file, "rb"))) {
         (void)fputs("Could not open MAC key file", stderr);
         goto add_arg;
      }
      #define r4 mac
         {
            ARCFOUR_STEP_1_KEY; ARCFOUR_STEP_2;
            {
               int c;
               while ((c= getc(key)) != EOF) {
                  ASSERT_MOD256(c);
                  ARCFOUR_STEP_4_KEY((unsigned)c);
                  ARCFOUR_STEP_5_DROP; ARCFOUR_STEP_7_KEY;
               }
            }
            if (ferror(key)) goto krderr;
            assert(feof(key));
            if (fclose(key)) goto exotic_error;
         }
      #undef r4
      current_file= 0;
   }
   switch (encrypt) {
      int out;
      case 0: /* Decryption. */
         {
            unsigned i;
            if (
               setvbuf(stdin, 0, _IONBF, 0) || setvbuf(stdout, 0, _IONBF, 0)
            ) {
               goto exotic_error;
            }
            for (;;) {
               int eof;
               unsigned stop;
               size_t want;
               {
                  size_t got= fread(
                        iobuf + prebuffered, sizeof *iobuf
                     ,  want= DIM(iobuf) - prebuffered
                     ,  stdin
                  );
                  if ((eof= got != want) && ferror(stdin)) goto rderr;
                  assert(got <= want);
                  got+= prebuffered;
                  if (mac_key_fname) {
                     if (got == MAC_OCTETS) {
                        assert(got < want);
                        break;
                     }
                     assert(got > MAC_OCTETS);
                     want= got - (prebuffered= MAC_OCTETS);
                  } else {
                     assert(prebuffered == 0);
                     want= got;
                  }
               }
               stop= (unsigned)want;
               assert(stop == want);
               for (i= 0; i < stop; ++i) {
                  int r;
                  out= (int)(unsigned)iobuf[i];
                  ASSERT_MOD256(out);
                  if (mac_key_fname) {
                     #define r4 mac
                        ARCFOUR_STEP_4_KEY((unsigned)out);
                        ARCFOUR_STEP_5_DROP; ARCFOUR_STEP_7_KEY;
                     #undef r4
                  }
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
                  ASSERT_MOD256(out);
                  iobuf[i]= (unsigned char)(unsigned)out;
               }
               if (stop) {
                  if (fwrite(iobuf, sizeof *iobuf, want, stdout) != want) {
                     goto wrerr;
                  }
               }
               (void)memmove(iobuf, iobuf + want, prebuffered);
               if (eof) break;
            }
            if (mac_key_fname) {
               if (prebuffered != MAC_OCTETS) {
                  assert(prebuffered < MAC_OCTETS);
                  error= "Missing MAC at end of input stream!"; goto fail;
               }
               #define r4 mac
                  ARCFOUR_STEP_2;
                  DROP_INITIAL_KEYSTREAM();
                  for (i= 0; i < MAC_OCTETS; ++i) {
                     int r;
                     CSPRNG_GET(out);
                     CSPRNG_GET(r);
                     out^= r;
                     CSPRNG_GET(r);
                     ADD_MOD256(out, r);
                     ASSERT_MOD256(out);
                     if (iobuf[i] != (unsigned)out) {
                        error= "MAC mismatch! Message has been corrupted.";
                        goto fail;
                     }
                  }
               #undef r4
            }
         }
         break;
      default: /* Encryption. */
         assert(encrypt == 1);
         while ((out= getchar()) != EOF) {
            {
               int r0, r1, r2;
               ASSERT_MOD256(out);
               CSPRNG_GET(r0);
               CSPRNG_GET(r1);
               CSPRNG_GET(r2);
               SUB_MOD256(out, r2);
               out^= r1;
               SUB_MOD256(out, r0);
            }
            ASSERT_MOD256(out);
            if (putchar(out) != out) goto wrerr;
            #define r4 mac
               ARCFOUR_STEP_4_KEY((unsigned)out);
               ARCFOUR_STEP_5_DROP; ARCFOUR_STEP_7_KEY;
            #undef r4
         }
         break;
   }
   if (ferror(stdin)) goto rderr;
   assert(feof(stdin));
   if (encrypt == 1 && mac_key_fname) {
      #define r4 mac
         ARCFOUR_STEP_2;
         DROP_INITIAL_KEYSTREAM();
         {
            unsigned mac_cnt;
            for (mac_cnt= MAC_OCTETS; mac_cnt--; ) {
               int out, r;
               CSPRNG_GET(out);
               CSPRNG_GET(r);
               out^= r;
               CSPRNG_GET(r);
               ADD_MOD256(out, r);
               ASSERT_MOD256(out);
               if (putchar(out) != out) goto wrerr;
            }
         }
      #undef r4
   }
   cleanup:
   if (fflush(0)) {
      wrerr: error= "Error writing to standard output!";
      fail:
      (void)fputs(error, stderr);
      (void)fputs("\n" "Use option -h for displaying help.\n", stderr);
   }
   leave:
   return error ? EXIT_FAILURE : EXIT_SUCCESS;
}
