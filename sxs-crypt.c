#define VERSTR_1 "Version 2020.336"
#define VERSTR_2 "Copyright (c) 2020 Guenther Brunthaler."

static char help[]= { /* Formatted as 66 output columns. */
   "sxs-crypt - SUBTRACT-XOR-SUBTRACT encryption/decryption\n"
   "\n"
   "The program encrypts binary data plaintext or decrypts binary\n"
   "data ciphertext and writes the binary result to standard output.\n"
   "Note that actual text data is a subset of binary data and will\n"
   "therefore also work as plaintext.\n"
   "\n"
   "Usages:\n"
   "\n"
   "sxs-crypt -e <r0> <r1> <r2> < <plaintext> > <ciphertext>\n"
   "sxs-crypt -d <r0> <r1> <r2> < <ciphertext> > <plaintext>\n"
   "\n"
   "Supported options:\n"
   "\n"
   "-e: Selects encryption mode\n"
   "-d: Selects decryption mode\n"
   "-h: Display this help and exit\n"
   "-V: Display version information and exit\n"
   "\n"
   "The binary data to be encrypted or decrypted will be read\n"
   "from standard input and the result will be written to standard\n"
   "output.\n"
   "\n"
   "The arguments <r0>, <r1> and <r2> are the pathnames of streams\n"
   "(files, special files or pipes like those found in /dev/fd/ on\n"
   "Linux systems) which must have (at least) the same size as the\n"
   "stream read from standard input. They must have been generated\n"
   "by cryptographically secure pseudorandom generators.\n"
   "\n"
   "Every stream cipher (such as ARCFOUR-drop-3072 or treyfer-ofb)\n"
   "can be made into such a CSPRNG by encrypting a stream of\n"
   "zero-bytes (such as read from /dev/zero).\n"
   "\n"
   "The advantage of employing SXS over using the stream ciphers\n"
   "directly is that bit-flipping attacks are no longer effective.\n"
   "\n"
   "SXS-encryption processes one octet from each of four input\n"
   "streams in parallel, producing the next output octet:\n"
   "\n"
   "Let P[i], C[i], R0[i], R1[i] and R2[i] represent the <i>th octet\n"
   "of <plaintext>, <ciphertext>, <r0>, <r1> and <r2>, respectively.\n"
   "\n"
   "Then SXS-encryption is defined as follows:\n"
   "\n"
   "C[i] := ((P[i] - R2[i]) ^ R1[i]) - R0[i]\n"
   "\n"
   "And SXS-decryption is defined as this:\n"
   "\n"
   "P[i] := ((C[i] + R0[i]) ^ R1[i]) + R2[i]\n"
   "\n"
   "where '^' is the bitwise XOR-operation, '+' is addition modulo\n"
   "256, and '-' is subtraction modulo 256.\n"
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

#include <dim_sdbrke8ae851uitgzm4nv3ea2.h>
#include <getopt_nh7lll77vb62ycgwzwf30zlln.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#define ADD_MOD256(v, inc) ((v)= (v) + (inc) & 256 - 1)
#define SUB_MOD256(v, dec) ADD_MOD256(v, 256 - (dec))
#define ASSERT_MOD256(c) assert((c) >= 0); assert((c) < 256)
#define READ_CSPRNG(c, i) { \
   if (((c)= fgetc(r[i])) == EOF) { \
      ea= (i); goto read_stream_error; \
   } \
   ASSERT_MOD256(c); \
}

int main(int argc, char **argv) {
   char const *error= 0;
   int a= 0, ea, encrypt= -1;
   FILE *r[3];
   for (ea= (int)DIM(r); ea--; ) r[ea]= 0;
   {
      int optpos= 0;
      for (;;) {
         int opt;
         switch (opt= getopt_simplest(&a, &optpos, argc, argv)) {
            case 0: goto no_more_options;
            case 'e': if (encrypt == 0) goto usage; encrypt= 1; break;
            case 'd': if (encrypt == 1) goto usage; encrypt= 0; break;
            case 'h': usage: (void)fputs(help, stderr); /* Fall through. */
            case 'V': error= version_info; goto fail;
            default: getopt_simplest_perror_opt(opt); goto leave;
         }
      }
   }
   read_stream_error:
   if (ferror(r[ea])) {
      (void)fputs("Error reading from", stderr);
   } else {
      (void)fputs(
         "Premature end of stream encountered while reading from", stderr
      );
   }
   add_nonarg:
   ea+= a;
   add_arg:
   (void)fputs(" \"", stderr);
   (void)fputs(argv[ea], stderr);
   error= "\"!";
   goto fail;
   no_more_options:
   {
      int i;
      for (i= 0; i < (int)DIM(r); ++i) {
         if (a + i == argc) goto usage;
         assert(a + i < argc);
         if (!(r[i]= fopen(argv[a + i], "rb"))) {
            (void)fputs("Could not open", stderr);
            ea= a + i; goto add_arg;
         }
      }
      if (a + i != argc) goto usage;
   }
   switch (encrypt) {
      int out;
      case 1: /* Encryption. */
         while ((out= getchar()) != EOF) {
            int c;
            ASSERT_MOD256(out);
            READ_CSPRNG(c, 2);
            SUB_MOD256(out, c);
            READ_CSPRNG(c, 1);
            out^= c;
            READ_CSPRNG(c, 0);
            SUB_MOD256(out, c);
            if (putchar(out) != out) goto wrerr;
         }
         break;
      case 0: /* Decryption. */
         while ((out= getchar()) != EOF) {
            int c;
            ASSERT_MOD256(out);
            READ_CSPRNG(c, 0);
            ADD_MOD256(out, c);
            READ_CSPRNG(c, 1);
            out^= c;
            READ_CSPRNG(c, 2);
            ADD_MOD256(out, c);
            if (putchar(out) != out) goto wrerr;
         }
         break;
      default: goto usage;
   }
   if (ferror(stdin)) { error= "Error reading standard input!"; goto fail; }
   assert(feof(stdin));
   if (fflush(0)) {
      wrerr: error= "Error writing to standard output!";
      fail:
      (void)fputs(error, stderr);
      (void)fputc('\n', stderr);
   }
   leave:
   for (ea= (int)DIM(r); ea--; ) {
      FILE *fh;
      if (fh= r[ea]) {
         r[ea]= 0;
         if (fclose(fh)) {
            (void)fputs("Error closing input stream", stderr);
            goto add_nonarg;
         }
      }
   }
   return error ? EXIT_FAILURE : EXIT_SUCCESS;
}
