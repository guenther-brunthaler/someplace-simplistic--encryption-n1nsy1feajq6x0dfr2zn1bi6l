#! /bin/sh
version() {
	cat << ===
Version 2021.322

Copyright (c) 2021 Guenther Brunthaler. All rights reserved.

This script is free software.
Distribution is permitted under the terms of the GPLv3.
===
}

help() {
	cat << ===
$APP - modified ARCFOUR using SUBTRACT-XOR-SUBTRACT instead of just XOR|
|
Usage: $APP <options>|
|
The binary octet data (octets are 8-bit bytes) to be encrypted or decrypted |
will be read from standard input and the binary result will be written to |
standard output.|
|
|
Supported options:|
|
-E <one_time_key>: Selects raw encryption mode. Minimally slower then |
decryption. <one_time_key> is the pathname of a file containing the binary |
encryption key. This key must only be used for encrypting one specific |
message. It must not be reused for encrypting a different message.|
|
-D <one_time_key>: Selects raw decryption mode. Also recommended for hashing. |
See the explanation for -E about <one_time_key>, except that it is used for |
decryption in this mode.|
|
-M <one_time_mac_key>: Create or verify a MAC, using the specified pathname |
for obtaining the binary MAC key. This key (of arbitrary size, but 211 octets |
are recommended) will be prepended to the encrypted data, and the concatenated |
result will be hashed yielding a 32-octet MAC. In encryption mode this MAC |
will be appended after the end of the encrypted data; in decryption mode it |
will be verified (an error will be raised if the calculated MAC does not match |
the stored MAC). The hashing itself will use a separate instance of the |
decryption algorithm, independent from the instance of the main operation mode |
(-D or -E).|
|
-h: Display this help and exit|
-V: Display version information and exit|
|
For all options which take the pathname of a key file as an argument, special |
files like '/dev/fd/9' are also eligible. This allows to read the binary keys |
or the data to be hashed from redirected file descriptors rather than from |
real files.|
|
Although keys of any size are supported and every octet of a key will have an |
effect on the encryption, even the longest keys will not be more secure than |
211-octet (1684 bit) full-entropy random binary keys (such as taken from from |
'/dev/random').|
|
This program uses ARCFOUR-drop3072 as a CSPRNG (cryptographically secure |
pseudo-random generator) and takes the next three octets (R0, R1 and R2) of |
its pseudo-random stream in order to raw encrypt/decrypt the next |
plaintext/ciphertext octet P/C as follows:|
|
C = ((P - R2) ^ R1) - R0|
|
P = ((C + R0) ^ R1) + R2|
|
where '^' is the bitwise XOR-operation, '+' is addition modulo 256, and '-' is |
subtraction modulo 256.|
|
ARCFOUR-drop3072 is the same as original ARCFOUR except that the first 3072 |
output octets are thrown away and not used for actual encryption/decryption. |
This protects against some known attacks.|
|
This program also uses a modification of the original ARCFOUR key schedule |
which actually makes it simpler: All octets of the key are processed exactly |
once. No attempt is made to recycle shorter keys than 256 octets, nor will key |
octets beyond the 256th be ignored.|
|
Note this program can also used for hashing: Use the data to be hashed as the |
binary key and encrypt or decrypt some constant octet string with it. The |
resulting octet string is then the hash value. This program decrypts minimally |
faster than it can encrypt, therefore it is recommended to always use |
decryption for hashing. The size of the constant octet string will be the same |
as the hash output size. For simplicity, it is recommended to use binary zero |
octets as the constant string to be decrypted. In particular, '/dev/zero' can |
be used to obtain such zero octets via 'dd'.|
|
The program can also derive one-time keys for both data encryption and MAC |
calculation of some specific message from a long-term binary key and a binary |
per-message salt: Concatenate a 106-octet pre-salt with the long-term key and |
a 106-octet post-salt and hash the result into 424 octets: A 212 octet |
one-time encryption key and a 212 octet one-time MAC key.|
|
You can derive a long-term binary key from a long-term password by stripping |
any newline character from it and and converting it into UTF-8, NFKC |
(normalization form compatibility composition). The utilities 'idn' and |
'uconv' can convert into NFKC. If the passwords are restricted to ASCII no |
such normalization will be necessary as it will make no difference then.|
|
The program can also be used for salt stretching: Hash a shorter salt (say 32 |
octets) into as much salt octets of hash output as there are required (say 106 |
+ 106 = 212 octets).|
|
It is also possible to create a MAC (message authentication code): Prepend a |
32-octet MAC key before the message to be authenticated, and hash the |
concatenated result. The hash digest then represents the MAC. Similar to the |
encryption key, the MAC key must not be used to integrity-protect the contents |
of more than one particular message. It is a one-time key, too. Also, MAC keys |
must not be re-used as encryption keys. Neither for the same or other |
messages. Not ever.|
|
If a salt is used for encryption, it is recommended to prepend a 32-octet salt |
before the encrypted message.|
|
If a MAC is used to integrity-protect a message, it is recommended to append a |
32-octet MAC after the encrypted data.|
|
If a message shall be both encrypted and MAC-protected, it is recommended to |
calculate the MAC over the already-encrypted message ('encrypt-then-MAC').|
|
A salt can be created by hashing the concatenation of a message counter and an |
account hash into 32 octets of salt. Alternatively, the output of 'LC_ALL=C |
date -u' can be used instead of a counter.|
|
The account hash is a 32 octet hash which should include at least the |
following information: Fully-qualified host name, login name, UTC date/time of |
hash creation. You can add additional info also, such as the output of 'ps |
-Alf' and 'df'. This hash needs only be calculated once per account.|
===
}
APP=${0##*/}

set -e
trap 'test $? = 0 || echo "\"$0\" failed!" >& 2' 0

show() {
	fold -sw 66
}

exit_version() {
	version | show; exit $1
}

exit_help() {
	help | sed 's/ |$/ /' | tr -d '\n' | tr '|' '\n' | show
	echo; exit_version "$@"
}

encrypt=
mac=
while getopts D:E:M:hV opt
do
	case $opt in
		D) key=$OPTARG; encrypt=false;;
		E) key=$OPTARG; encrypt=true;;
		M) mac=$OPTARG;;
		h) exit_help;;
		V) exit_version;;
		*) false || exit
	esac
done
shift `expr $OPTIND - 1 || :`

test "$encrypt"

case $# in
	0) ;;
	*) exit_help `false || echo $?` >& 2
esac

test -z "$mac" # Not yet implemented.

bin=$0
if test ! -e "$bin"
then
	bin=`command -v -- "$bin"`
	test -e "$bin"
fi
bin=`dirname -- "$bin"`
case $bin in
	-*) bin=./$bin
esac

{
	sh "$bin"/raw2dec < "$key"
	echo D 3072 R 3 T
	sh "$bin"/raw2dec
} \
| sh "$bin"/rc4csprng10 \
| case $encrypt in
	true)
		 sh "$bin"/rvscyc10 3 1 \
		 | sh "$bin"/rvscyc10 4 \
		 | sh "$bin"/rvscyc10 2 2 \
		 | sh "$bin"/mod256sub10 2 \
		 | sh "$bin"/xor10 1 \
		 | sh "$bin"/rvscyc10 2 \
		 | sh "$bin"/mod256sub10
		;;
	*)
		sh "$bin"/rvscyc10 4 \
		| sh "$bin"/mod256add10 2 \
		| sh "$bin"/xor10 1 \
		| sh "$bin"/mod256add10 
esac \
| sh "$bin"/dec2raw
