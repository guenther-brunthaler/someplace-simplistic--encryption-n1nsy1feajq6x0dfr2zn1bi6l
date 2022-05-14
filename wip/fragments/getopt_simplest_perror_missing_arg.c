/* v2020.322 */

#include <getopt_nh7lll77vb62ycgwzwf30zlln.h>
#include <stdio.h>

void getopt_simplest_perror_missing_arg(int option_char) {
   (void)fputs("Missing mandatory argument for option -", stderr);
   (void)fputc(option_char, stderr);
   (void)fputs("!\n", stderr);
}
