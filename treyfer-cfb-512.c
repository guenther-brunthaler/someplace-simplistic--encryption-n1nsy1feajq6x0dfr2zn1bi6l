#define VERSTR "Version 2022.67"
#define COPYRIGHT_NOTICE "Copyright (c) 2021-2022 Guenther Brunthaler."

static char help[]= { /* Formatted as 66 output columns. */
   "treyfer-cfb-512 - Encrypt or decrypt binary data with a 512 bit\n"
   "key.\n"
   "\n"
   "In both cases a binary 64-byte long-term key is read from standard\n"
   "input first. Then a 64-byte initialization vector (IV) is read,\n"
   "followed by the data to be encrypted or decrypted. The result will\n"
   "be written to standard output. Command line arguments are not\n"
   "used.\n"
   "\n"
   "The IV is arbitrary data and does not need to be kept secret, but\n"
   "the same IV must never be used for encrypting more than a single\n"
   "message using the same long-term key. The receiver needs to know\n"
   "the IV for decrypting the message. It is recommended to prepend\n"
   "the IV in front of the encrypted data when sending the encrypted\n"
   "message to to the receiver.\n"
   "\n"
   "One way to ensure the IV is always unique is to use as message\n"
   "counter padded to 64 bytes as the IV. Another way is to use the\n"
   "the current date and time instead of the counter. Yet another way\n"
   "is to use 64 bytes obtained from /dev/random as the IV.\n"
   "\n"
   "This program (ab)uses the 'Treyfer' MAC algorithm as an\n"
   "encryption-only block cipher except that both the key and block\n"
   "size has been increased from 64 to 512 bit, and the number of\n"
   "rounds has been increased by the same factor. This Treyfer\n"
   "implementation has been configured to use a constant s-box derived\n"
   "from the digits of pi.\n"
   "\n"
   "This block cipher is then run in the CFB mode of operation,\n"
   "turning it into a stream cipher which can be used for both\n"
   "encryption and decryption and does not require any padding.\n"
   "\n"
   "" VERSTR "\n"
   "\n"
   "" COPYRIGHT_NOTICE " All rights reserved.\n"
   "\n"
   "This source file is free software.\n"
   "Distribution is permitted under the terms of the GPLv3.\n"
};

#include "config.h"
#include "treyfer_sbox.h"
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <assert.h>

#define BUFFER_SIZE (64 * 1024)

#define DIM(array) (sizeof(array) / sizeof *(array))

int main(int argc, char **argv) {
   unsigned char key[512 / 8], block[512 / 8], *buffer, *dst;
   int eof_allowed;
   unsigned base, left, bytes_read;
   char const *error;
   enum {
         initial, release, die, read_key, read_something, read_iv, init_cfb
      ,  encrypt_block, read_buffer, cfb_buffer, cfb_segment, finished
   } state= initial, followup_state;
   (void)argv;
   if (argc > 1) {
      if (fputs(help, stdout) < 0) goto raise_write_error;
      state= finished;
   }
   for (;;) {
      switch (state) {
         case initial: /* Allocate the I/O buffer. */
            if (buffer= malloc(BUFFER_SIZE)) { state= read_key; break; }
            error= "Out of memory!";
            fail:
            (void)fputs(error, stderr);
            (void)fputc('\n', stderr);
            followup_state= die; /* state= release; */
            /* Fall through. */
         case release: /* Free the I/O buffer. */
            free(buffer); /* Won't hurt even if the buffer is null. */
            state= followup_state;
            break;
         case die: /* Terminate due to failure. */
            return EXIT_FAILURE;
         case read_key: /* Read the key. */
            dst= key; bytes_read= (unsigned)sizeof key; eof_allowed= 0;
            followup_state= read_iv; /* state= read_something; */
            /* Fall through. */
         case read_something: /* Read from standard input. */
            {
               size_t read;
               if (
                  (read= fread(dst, sizeof *dst, bytes_read, stdin))
                  != bytes_read
               ) {
                  if (ferror(stdin)) { error= "Read error!"; goto fail; }
                  assert(feof(stdin));
                  if (!eof_allowed) {
                     error= "Input is too short!"; goto fail;
                  }
                  assert(read < bytes_read);
                  bytes_read= (unsigned)read;
                  assert(bytes_read == read);
               }
            }
            state= followup_state;
            break;
         case read_iv: /* Read the IV into block[]. */
            dst= block; bytes_read= sizeof block;
            assert(!eof_allowed);
            followup_state= init_cfb; state= read_something;
            break;
         case init_cfb: /* Initialize CFB by encrypting the IV. */
            eof_allowed= 1; /* Will stay like this from now on. */
            followup_state= read_buffer; /* state= encrypt_block; */
            /* Fall through. */
         case encrypt_block: /* Encrypt the block[] with Treyfer. */
            #define MOD(x, m) ((unsigned char)(x) & (unsigned char)((m) - 1))
            #define MOD_A(x, array) MOD(x, DIM(array))
            #define ORIGINAL_BLOCK_BITS 64
            #define ORIGINAL_ROUNDS 32
            #define FACTOR_BIGGER 8
            #define NUMROUNDS (ORIGINAL_ROUNDS * FACTOR_BIGGER)
            assert(ORIGINAL_BLOCK_BITS * FACTOR_BIGGER == DIM(block) * 8);
            {
               unsigned i= 0;
               unsigned char t= block[0];
               for (i= 0; i < ORIGINAL_BLOCK_BITS / 8 * NUMROUNDS; ) {
                  /* This is the core of the Treyfer algorithm. */
                  t= t + key[MOD_A(i, key)] & 0xff;
                  assert(t < DIM(sbox));
                  ++i; t= MOD_A(sbox[t] + block[MOD_A(i, block)], sbox);
                  /* ROT-L by 1 bit. */
                  block[MOD_A(i, block)]= t= (unsigned char)(
                     t + t & 0xff | t >> CHAR_BIT - 1
                  );
               }
            }
            #undef NUMROUNDS
            #undef FACTOR_BIGGER
            #undef ORIGINAL_ROUNDS
            #undef ORIGINAL_BLOCK_BITS
            #undef MOD_A
            #undef MOD
            state= followup_state;
            break;
         case read_buffer:
            /* Main loop. Try to read the next buffer of input. */
            dst= buffer; bytes_read= BUFFER_SIZE;
            assert(eof_allowed);
            followup_state= cfb_buffer; state= read_something;
            break;
         case cfb_buffer: /* CFB-encrypt the next buffer, unless empty. */
            if (!bytes_read) {
               /* EOF. */
               followup_state= finished; state= release;
               break;
            }
            base= 0; /* state= cfb_segment; */
            /* Fall through. */
         case cfb_segment: /* CFB-encrypt next buffer segment. */
            assert(base < bytes_read);
            if ((left= bytes_read - base) > DIM(block)) {
               left= (unsigned)DIM(block);
               assert(left == DIM(block));
            }
            assert(left >= 1);
            /* XOR current buffer segment with encrypted last block.
             * Then replace the block contents with the updated segment. */
            {
               unsigned i;
               for (i= 0; left--; ++i) {
                  block[i]= buffer[base++]^= block[i];
               }
            }
            if (base != bytes_read) {
               assert(base < bytes_read);
               /* Encrypt the block just queued for output later in
                * order to prepare for next CFB segment. Then process
                * next segment. */
               followup_state= cfb_segment; state= encrypt_block;
               break;
            }
            /* Processing of buffer is complete. Output the buffer. */
            if (
               fwrite(buffer, sizeof *buffer, bytes_read, stdout) != bytes_read
            ) {
               assert(ferror(stdout));
               raise_write_error:
               error= "Write error!"; goto fail;
            }
            state= read_buffer; /* Advance to the next buffer load. */
            break;
         default:
            assert(state == finished);
            if (fflush(stdout)) goto raise_write_error;
            return EXIT_SUCCESS;
      }
   }
}
