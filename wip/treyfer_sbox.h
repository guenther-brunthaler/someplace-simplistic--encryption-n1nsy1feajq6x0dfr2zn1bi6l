/* Our "nothing up my sleeve" s-box
 *
 * The s-box contents have been generated by a "nothing-up my sleeve"
 * pseudorandom number generator, driving the most basic algorithm imaginable
 * for setting up any s-box.
 *
 * The pseudorandom-generator consists of delivering the binary digits of
 * Pi as individual octets, starting with its most significant bit.
 *
 * The most basic s-box setup consists of initializing the s-box to the
 * identity permuation. Then make a pass over all of the elements of the
 * s-box: Swap the s-box entry at the current position with the entry indexed
 * by the next-pseudorandom number.
 *
 * Finally, output the s-box entries as character array initializers.
 *
 * The following shell command pipeline does all of the above:
 *
 * $ echo 'scale= l(2 ^ (256 * 8 + 10)) / l(2); p= 4 * a(1); '`:
 * `'while (p > 0.5) p/= 2; p*= 2 ^ (256 * 8); scale= 0; p/= 1; '`:
 * `'for (i= 256; i--; ) {s[i]= i; r[i]= p % 256; p/= 256}; '`:
 * `'for (i= 0; i != 256; ++i) {'`:
 *    `'t= s[i]; s[i]= s[j= r[i]]; s[j]= t'`:
 * `'}; '`:
 * `'for (i= 0; i != 256; ++i) s[i]' | bc -l | awk '
 * s == "" {o= "   ,  I2C8("}
 * s != "" {o= o ", "}
 * {++s; o= o sprintf("%3s", $0)}
 * s == 8 {s= ""; print o ")"}'
 *
 * and its output can be seen below: */

#define I2C(i) (char)(unsigned char)(unsigned)(i)
#define I2C8(i1, i2, i3, i4, i5, i6, i7, i8) \
   I2C(i1), I2C(i2), I2C(i3), I2C(i4), I2C(i5), I2C(i6), I2C(i7), I2C(i8)

static char const sbox[256]= {
      I2C8(113, 191,  44, 197, 147,  25,  97, 189)
   ,  I2C8( 71,  99, 232, 142, 227, 110, 144, 104)
   ,  I2C8( 21, 129,  39, 201,  11, 198, 208,   5)
   ,  I2C8(135,  88, 162,  79, 216, 183, 205, 119)
   ,  I2C8( 40,  74,  63, 160,  84, 164,  73,  13)
   ,  I2C8(245, 206,  52, 217,  22, 235, 165,  28)
   ,  I2C8(152,  17,   3, 106, 128,  90, 170, 120)
   ,  I2C8(167, 240, 154, 150,  59, 108, 109,  70)
   ,  I2C8(242,  66, 149,   1,  93, 236,  19, 234)
   ,  I2C8(117, 237, 221, 111, 228,  55, 246,   6)
   ,  I2C8( 75,  47, 174,  91,  72,   2,  27,  78)
   ,  I2C8( 32,  29, 141, 253, 115, 254,  33, 210)
   ,  I2C8(215, 181,  42,  98, 185, 172, 143,  35)
   ,  I2C8(199,   4, 153, 247,  87, 121, 157, 158)
   ,  I2C8( 62, 100, 118, 173,  50, 220, 196, 130)
   ,  I2C8( 61,  80,  15,  77,  14,  95, 132,  30)
   ,  I2C8(249, 139, 244, 155, 233,   8, 103, 175)
   ,  I2C8(231, 178, 224,  64,  96, 255,  86, 203)
   ,  I2C8(250,  68, 114, 136,  23, 218,  67,  51)
   ,  I2C8( 94, 156, 148, 212, 184, 116,  45, 138)
   ,  I2C8(179, 243,  37,  56, 200, 207,  12,  38)
   ,  I2C8(204, 186, 159,  34, 213, 192,  41,   0)
   ,  I2C8(180, 122,  20,  60,  58, 222, 134, 137)
   ,  I2C8(241, 112, 182, 169,  92,  26, 219,  24)
   ,  I2C8(127, 194, 171, 209,   7,  85, 195,   9)
   ,  I2C8( 65, 226,  43, 248,  83, 211, 202, 190)
   ,  I2C8(239,  10, 229, 251, 102,  76,  57, 238)
   ,  I2C8( 89, 105, 101, 187, 177, 131, 123, 225)
   ,  I2C8( 82, 126,  16, 188, 166, 140, 163, 193)
   ,  I2C8( 49,  48,  36,  18,  53,  81, 146, 252)
   ,  I2C8( 69,  54,  31, 161, 145, 107, 168, 176)
   ,  I2C8( 46, 125, 124, 223, 230, 214, 151, 133)
};

#undef I2C8
#undef I2C
