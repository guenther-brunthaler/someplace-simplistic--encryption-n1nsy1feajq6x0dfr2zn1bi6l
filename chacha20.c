static char version[] = {
   "{APP} Version 2023.148.1\n"
   "Copyright (c) 2023 Guenther Brunthaler. All rights reserved.\n"
   "\n"
   "This source file is free software.\n"
   "Distribution is permitted under the terms of the GPLv3.\n"
};

static char help[] = {
   "A ChaCha20 implementation.\n"
   "\n"
   "{APP} encrypts or decrypts arbitrary data read from standard input and "
   "writes the result to standard output.\n"
   "\n"
   "Before the data to be encrypted or decrypted, the following encryption "
   "parameters will be read from standard input:\n"
   "\n"
   "[ 'P' <8 octets starting offset> ]\n"
   "'K' <32 octets binary encryption key>\n"
   "'N' <32 octets binary nonce>\n"
   "'D' <the data to be encrypted/decrypted> ...\n"
   "\n"
   "where the characters between the quotes must be specified as-is in ASCII "
   "encoding. They label the binary data sequences following them which are "
   "indicated by the text between the angle brackets in the text above.\n"
   "\n"
   "The data for 'N' can be arbitrary data but it must be a nonce. This "
   "means that you must be sure this data is never repeated for an earlier "
   "or future invocation of the program; at least not with the same key. A "
   "simple way to ensure this is to use a counter, the current date/time or "
   "a true random number as a nonce. The nonce is required for later "
   "decryption like the key. But unlike the key it does not need to be kept "
   "secret. In fact, the nonce is usually stored along with the encrypted "
   "date, prefixing it. But this is up the user to decide. It can also be "
   "stored in a separate file.\n"
   "\n"
   "The square brackets around the 'P' sequence mean this parameter sequence "
   "is optional. If omitted, a starting 64-bit-block offset of zero is "
   "assumed. If the starting 64-bit-block offset is provided, however, then "
   "it must be specified in big endian byte order (from most to least "
   "significant octet).\n"
   "\n"
   "Note that this offset does not mean any bytes will be skipped from the "
   "data read from standard input. Instead it means that this data has been "
   "extracted from a larger data stream by the user starting at the "
   "specified 64-bit-block offset.\n"
};

#if !defined __STDC_VERSION__ || __STDC_VERSION__ < 199901
   #error "This source file requires a C99 compliant C compiler!"
#endif

#ifdef HAVE_CONFIG_H
   #include "config.h"
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#ifdef HAVE_TERMIOS_H
   #include <termios.h>
#endif
#ifdef GWINSZ_IN_SYS_IOCTL
   #include <sys/ioctl.h>
#endif
#ifdef HAVE_UNISTD_H
   #include <unistd.h>
#endif

static void *buffer;

static void release_resources(void) {
   free(buffer);
}

/* <eprefix> may be null if strerror(<errno>) alone already says it all. */
static void io_die(char const *eprefix) {
   if (errno) perror(eprefix);
   release_resources();
   exit(EXIT_FAILURE);
}

static void die(char const *format, ...) {
   {
      va_list args;
      va_start(args, format);
      (void)vfprintf(stderr, format, args);
      va_end(args);
   }
   (void)fputc('\n', stderr);
   release_resources();
   exit(EXIT_FAILURE);
}

static void write_ck(void const *src, size_t bytes) {
   if (fwrite(src, sizeof(char), bytes, stdout) != bytes) {
      io_die("Output error");
   }
}

static void emit_wrapping(
   char *line, int *column_ref, int columns, char const *text, size_t tlen
) {
   int column = *column_ref;
   while (tlen) {
      size_t btc;
      if (tlen < (btc = columns - column)) btc = tlen;
      (void)memcpy(line + column, text, btc);
      text += btc; tlen -= btc;
      if ((column += btc) == columns) {
         /* Line buffer is full. We need to output something. */
         int i;
         for (i = column; i--; ) {
            if (line[i] != '\n') continue;
            /* We have found the last newline in the buffer. Output all
             * the lines in the buffer up to that newline. */
            write_ck(line, ++i);
            memmove(line, line + i, columns - i);
            column -= i;
            break;
         }
         if (column == columns) {
            /* No newlines - we need to actually wrap a line. */
            for (i = column - 1; i--; ) {
               if (line[i] != ' ') continue;
               /* We have found the last space in the buffer (that is not also
                * the last character in the buffer). Replace the character
                * following it temporarily with a newline and output the line
                * up to that newline. */
               {
                  char save = line[++i];
                  line[i] = '\n';
                  write_ck(line, i + 1);
                  line[i] = save;
               }
               memmove(line, line + i, columns - i);
               column -= i;
               break;
            }
         }
         if (column == columns) {
            /* No way to wrap the line either. Replace the last column
             * with a backslash and emit the line up to there. */
            {
               char save = line[i = column - 1];
               line[i] = '\\';
               write_ck(line, i + 1);
               line[i] = save;
            }
            /* Restore the character which has been replaced by the backslash
             * and write a newline before it into the buffer. Make this the
             * first new character of the new buffer. */
            line[--i] = '\n';
            memmove(line, line + i, columns - i);
            column -= i;
         }
      }
      assert(column < columns);
   }
   *column_ref = column;
}

static void exit_usage(char const *app) {
   static char const *const output[] = {help, "\n", version, 0};
   static char const trigger[] = {"{APP}"};
   char const* const *messages = output;
   int columns = 0;
   {
      char const *cols;
      if (!!(cols = getenv("COLUMNS"))) columns = atoi(cols);
   }
   if (!columns && isatty(STDOUT_FILENO)) {
      struct winsize w;
      if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) != -1) columns = w.ws_col;
   }
   if (!columns) columns = 66;
   {
      char const *msg = *messages++;
      int column = 0;
      char *line;
      size_t alen = strlen(app);
      if (!(line = buffer = malloc(columns))) {
         io_die("Memory allocation failure");
      }
      for (;;) {
         char const *found;
         if (!(found = strstr(msg, trigger))) found = msg + strlen(msg);
         {
            size_t outnum = found - msg;
            emit_wrapping(line, &column, columns, msg, outnum);
            msg += outnum;
         }
         if (!*msg) {
            if (!(msg = *messages++)) break;
            continue;
         }
         msg += sizeof trigger - 1;
         emit_wrapping(line, &column, columns, app, alen);
      }
      if (column) {
         /* Flush the line buffer. */
         write_ck(line, column);
      }
   }
   release_resources();
   exit(EXIT_FAILURE);
}

static void raise_read_error(void) {
   io_die("Read error");
}

static int getchar_ck(void) {
   int c;
   if ((c = getchar()) == EOF) raise_read_error();
   return c;
}

static void die_expecting(int c) {
   die("Expecting '%s' as input!", c);
}

static void expect(int c) {
   if (getchar_ck() != c) die_expecting(c);
}

static void read_ck(void *dst, size_t bytes) {
   if (fread(dst, sizeof(char), bytes, stdin) != bytes) raise_read_error();
}

#ifdef WORDS_BIGENDIAN
   #define deserialize_w32 deserialize_big_endian_w32
   static void deserialize_w32(
      uint32_t *restrict out, int n, void const *restrict serialized
   ) {
      while (n--) {
         out[n] = *(uint32_t *)serialized;
         serialized = (uint32_t const *)serialized + 1;
      }
   }
#else
   #define deserialize_w32 deserialize_little_endian_w32
   static void deserialize_w32(
      uint32_t *restrict out, int n, void const *restrict serialized
   ) {
      (void)memcpy(out, serialized, n * sizeof *out);
   }
#endif

int main(int argc, char **argv) {
   static uint32_t state[16];
   #define CONST_O 0 
   #define CONST_N 4
   #define KEY_O (CONST_O + CONST_N)
   #define KEY_N 8
   #define POS_O (KEY_O + KEY_N)
   #define POS_N 2
   #define NONCE_O (POS_O + POS_N)
   #define NONCE_N 2
   assert(NONCE_O + NONCE_N == sizeof state / sizeof *state);
   if (argc > 1) exit_usage(argc ? argv[0] : "(unnamed_program)");
   {
      static char const as_good_as_any[] = {"expand 32-byte k"};
      deserialize_w32(state + CONST_O, CONST_N, as_good_as_any);
   }
   {
      int c;
      if ((c = getchar_ck()) == 'P') {
         {
            uint32_t w[POS_N];
            read_ck(w, POS_N * sizeof *w);
            #ifdef WORDS_BIGENDIAN
               deserialize_w32(state + POS_O, 1, w + 1);
               deserialize_w32(state + POS_O + 1, 1, w);
            #else
               deserialize_w32(state + POS_O, POS_N, w);
            #endif
         }
         expect('K');
      } else if (c != 'K') {
         die_expecting('K');
      }
   }
   {
      uint32_t w[KEY_N];
      read_ck(w, KEY_N * sizeof *w);
      deserialize_w32(state + KEY_O, KEY_N, w);
   }
   expect('N');
   {
      uint32_t w[NONCE_N];
      read_ck(w, NONCE_N * sizeof *w);
      deserialize_w32(state + NONCE_O, NONCE_N, w);
   }
   expect('D');
}
