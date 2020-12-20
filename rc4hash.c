#define VERSTR_1 "Version 2020.335.1"
#define VERSTR_2 "Copyright (c) 2020 Guenther Brunthaler."

static char help[]= { /* Formatted as 66 output columns. */
   "rc4hash - abuse ARCFOUR for hashing or for key stretching\n"
   "\n"
   "The program abuses the ARCFOUR-drop3072 stream cipher as a\n"
   "cryptographically non-secure hash algorithm which can generate a\n"
   "hash value of any desired size.\n"
   "\n"
   "This allows the program also to be used for key stretching by\n"
   "hashing the key into a hash value with the same size as the\n"
   "desired stretched key.\n"
   "\n"
   "'non-secure' means that the algorithm has not been checked\n"
   "whether it can withstand an attacker changing the hashed message\n"
   "in such a way that the same hash value results even though it is\n"
   "a different message now. Maybe it is secure in this regard; maybe\n"
   "not. Better assume the latter.\n"
   "\n"
   "The same is true as part of a HMAC construction with arbitrarily\n"
   "defined input block size, although it seems more likely that this\n"
   "might in fact be sufficiently secure.\n"
   "\n"
   "The program can however be used as a sufficiently secure regular\n"
   "checksum. For very small output sizes like 128 bit and less,\n"
   "regular CRCs should be preferred because they have mathematical\n"
   "guarantees about error detection which this program cannot\n"
   "provide.\n"
   "\n"
   "On the other hand, this program should be much faster than a\n"
   "cryptographically secure hash algorithm like MD5 or the\n"
   "SHA-variants while providing the same (actually: arbitrary) hash\n"
   "sizes as output. It might be slower for very small inputs though,\n"
   "because it has a relatively high startup overhead.\n"
   "\n"
   "Usage: rc4hash [ <options> ] [ <file1> ... ]\n"
   "\n"
   "where <file1> is the pathname of the first file to be hashed. If\n"
   "no files are specified at all, the program hashes all data sent\n"
   "to its standard input.\n"
   "\n"
   "The following <options> are supported:\n"
   "\n"
   "-x: The hash output uses hexadecimal representation, much like\n"
   "the output of the widely-employed 'sha256' utility. By default,\n"
   "the hash is written using a custom base-32 representation which\n"
   "is somewhat shorter than the output generated with -x.\n"
   "\n"
   "-r: Output the hash as raw binary 8-bit bytes (octets). This is\n"
   "not human-readable, but the most compact representation. Use it\n"
   "for key stretching where a binary stretched key is required.\n"
   "\n"
   "-b <bits>: Specify the desired digest size in bits. Will be\n"
   "rounded up to the next multiple of the output alphabet bit size\n"
   "(8 for option -r, 4 for -x, otherwise 5). The default output size\n"
   "is '-b 256'.\n"
   "\n"
   "-B <octets>: Specify the desired digest size as 8-bit bytes. This\n"
   "is the same as -b with with 8 times the argument value.\n"
   "\n"
   "-c <chars>: Specify the desired digest size directly as a number\n"
   "of output characters in the hash representation. The hash\n"
   "algorithm itself generates an endless number of output characters\n"
   "as the hash. Output stops when <chars> characters have been\n"
   "written as the digest representation.\n"
   "\n"
   "-h: Display this help and exit.\n"
   "\n"
   "-V: Display version information and exit.\n"
   "\n"
   "Note that although the algorithm can create hashes of any\n"
   "requested output size, it only has an internal state of\n"
   "floor(log2(256!)) bits, i. e. 1683 bits. While it will happily\n"
   "output hash digests much larger than this, the amount of\n"
   "information actually represented by the those digests will never\n"
   "exceed 1683 bits.\n"
   "\n"
   "There are several reasons why this program exists:\n"
   "\n"
   "* Claims of being cryptographically secure is not one of them\n"
   "\n"
   "* The algorithm is fast, at least for larger inputs (because of\n"
   "the relatively high startup overhead per input file/stream)\n"
   "\n"
   "* It is based on a well known algorithm, ARCFOUR, which has known\n"
   "deficiencies for certain usage cases but is otherwise still\n"
   "considered secure enough.\n"
   "\n"
   "* ARCFOUR is so simple that it seems highly unlikely that its\n"
   "designers could have managed to put an algorithmic backdoor into\n"
   "its design.\n"
   "\n"
   "* It is even so simple that the whole algorithm can be known be\n"
   "heart. A developer can remember all details required for later\n"
   "re-implementation without too much difficulty, even without\n"
   "access to the specification, existing source code or any kind of\n"
   "network. This might be an advantage in repressive regimes where\n"
   "cryptography is banned and cryptographic source code cannot be\n"
   "distributed without severe consequences. But as long as they\n"
   "cannot wipe the memories of their citizens, this program may\n"
   "still be re-implemented there from scratch.\n"
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

static char const b32custom_alphabet[]= {
   /*
   $ perl -e \
   'print join(", ", map "'\'\$_\''", grep /[^01OI]/, (A..Z, 0..9)), "\n"'
   */
      'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'
   ,  'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R'
   ,  'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
   ,  '2', '3', '4', '5', '6', '7', '8', '9'
};

static char const hex_alphabet[]= {
   /* $ perl -e 'print join(", ", map "'\'\$_\''", 0..9, A..F), "\n"' */
      '0', '1', '2', '3', '4', '5', '6', '7'
   ,  '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

int main(int argc, char **argv) {
   char const *error= 0;
   int a= 0;
   unsigned long digest_chars= 0;
   char const *alphabet= b32custom_alphabet;
   unsigned alphabet_bitmask= (int)DIM(b32custom_alphabet) - 1, alphabet_bits;
   ARCFOUR_VARDEFS(static);
   {
      int optpos= 0;
      unsigned long digest_bits= 256;
      for (;;) {
         int opt;
         switch (opt= getopt_simplest(&a, &optpos, argc, argv)) {
            case 0: goto no_more_options;
            case 'x':
               alphabet= hex_alphabet;
               alphabet_bitmask= (unsigned)DIM(hex_alphabet) - 1;
               break;
            case 'r': alphabet= 0; alphabet_bitmask= (1 << 8) - 1; break;
            case 'b': case 'B': case 'c':
               {
                  union {
                     char const *str;
                     long val;
                  } optarg;
                  if (!(optarg.str= getopt_simplest_mand_arg(
                     &a, &optpos, argc, argv
                  ))) {
                     getopt_simplest_perror_missing_arg(opt); goto leave;
                  }
                  if ((optarg.val= atol(optarg.str)) < 1) {
                     bad_digest_size:
                     error= "Invalid digest size requested!"; goto fail;
                  }
                  digest_bits= (unsigned long)optarg.val;
                  assert((long)digest_bits == optarg.val);
               }
               switch (opt) {
                  case 'c':
                     digest_chars= digest_bits; digest_bits= 0;
                     break;
                  case 'B':
                     {
                        unsigned long old= digest_bits;
                        if ((digest_bits<<= 3) <= old) goto bad_digest_size;
                     }
               }
               break;
            case 'h': (void)fputs(help, stderr); /* Fall through. */
            case 'V': error= version_info; goto fail;
            default: getopt_simplest_perror_opt(opt); goto leave;
         }
      }
      no_more_options:
      {
         unsigned bm;
         for (alphabet_bits= bm= 0; bm != alphabet_bitmask; ++alphabet_bits) {
            bm+= bm + 1;
         }
      }
      if (digest_bits) {
         digest_chars= (digest_bits + alphabet_bits - 1) / alphabet_bits;
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
      ARCFOUR_STEP_1_KEY;
      ARCFOUR_STEP_2;
      /* Process input as an (overly long) key to set. */
      {
         int c;
         while ((c= getchar()) != EOF) {
            assert(c >= 0); assert(c < SBOX_SIZE);
            ARCFOUR_STEP_4_KEY((unsigned)c);
            ARCFOUR_STEP_5_DROP;
            ARCFOUR_STEP_7_KEY;
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
            ARCFOUR_STEP_3_PRNG; ARCFOUR_STEP_4_PRNG; ARCFOUR_STEP_5_DROP;
         }
      }
      /* Produce the message digest. */
      {
         unsigned long k;
         unsigned buf, bufbits= 0;
         #ifndef NDEBUG
            buf= 0;
         #endif
         for (k= digest_chars; k--; ) {
            if (bufbits < alphabet_bits) {
               /* Append the bits of another ARCFOUR output octet to <buf>. */
               ARCFOUR_STEP_3_PRNG; ARCFOUR_STEP_4_PRNG; ARCFOUR_STEP_5_PRNG;
               buf= buf << 8 | ARCFOUR_STEP_6_PRNG();
               bufbits+= 8;
            }
            assert(bufbits >= alphabet_bits);
            {
               unsigned c= buf >> bufbits - alphabet_bits & alphabet_bitmask;
               if (alphabet) c= (unsigned)alphabet[c];
               bufbits-= alphabet_bits;
               if (putchar((int)c) != (int)c) goto wrerr;
            }
         }
         if (a < argc) {
            if (alphabet) if (putchar(' ') == EOF) goto wrerr;
            if (fputs(argv[a], stdout) < 0) goto wrerr;
            if (!alphabet) if (putchar('\0') == EOF) goto wrerr;
         }
         if (alphabet) if (putchar('\n') == EOF) goto wrerr;
      }
      if (!(++a < argc)) break;
   }
   if (fflush(0)) {
      wrerr: error= "Write error!";
      fail:
      (void)fputs(error, stderr);
      (void)fputc('\n', stderr);
   }
   leave: return error ? EXIT_FAILURE : EXIT_SUCCESS;
}
