/* v2020.322 */

#include <getopt_nh7lll77vb62ycgwzwf30zlln.h>
#include <stdio.h>

void getopt_simplest_perror_opt(int bad_option_char) {
   (void)fputs("Unsupported option -", stderr);
   (void)fputc(bad_option_char, stderr);
   (void)fputs("!\n", stderr);
}
