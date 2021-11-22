#! /bin/sh
version() {
	cat << ===
Version 2021.288

Copyright (c) 2021 Guenther Brunthaler. All rights reserved.

This script is free software.
Distribution is permitted under the terms of the GPLv3.
===
}

help() {
	cat << ===
$APP - encrypt or decrypt data with integrity checking|
|
$APP is a portable POSIX shell script for encryption with no hard dependencies |
on non-standard utilities. No source of high-quality random numbers needs to |
be available for safe usage.|
|
Usages:|
|
|
\$ $APP <key_file> < <plaintext> > <nonce+ciphertext+mac>|
|
\$ $APP <key_file> <nonce+ciphertext+mac> > <plaintext>|
|
\$ $APP <options> ...|
|
|
The first usage encrypts data read from standard input and writes the |
encrypted data to standard output.|
|
The second usage verifies the integrity of the encrypted file first. Only if |
that is successful it will decrypt the data and write the result to the |
standard output.|
|
The last usage performs special actions depending on the options.|
|
<key_file> may contain binary random key data or be a text file containing a |
pass phrase.|
|
The same <key_file> can safely be reused for encrypting multiple messages. A |
nonce will automatically be included when encrypting, ensuring that even |
multiple encryptions of an identical input will never result in the same |
encrypted output.|
|
|
Options supported:|
|
-V: Show version information and exit.|
-h: Display this help and exit.|
|
|
$APP is very slow and should therefore only be used for small amounts of data, |
such as binary key files, password lists and private text messages.|
|
Use it preferably in your initramfs or in other restricted environments where |
you cannot install or build more powerful software for the same purpose.|
|
As $APP is a portable shell script, it will run on all POSIX-like hardware |
platforms without change.|
|
Encrypted output will be 64 bytes larger than the unencrypted input, because a |
32-byte nonce will be prepended and a 32-byte MAC will be appended to the |
actual encrypted data.|
|
For encryption only, a nonce counter needs to be maintained. This counter will |
be incremented if it exists and is writable, or otherwise a new counter will |
be created.|
|
All such data will be stored in the application data directory |
"$APP_NAME-$APP_UUID", which itself will normally be stored in the data base |
directory "\$HOME/.local/share". But \$XDG_DATA_HOME can be exported in order |
to override the data base location.|
|
The current counter value will be stored in a file "$COUNTER_FILE" within the |
application data directory.|
|
A new counter always starts with the value 0, but it will be encrypted before |
being used as a nonce with the encryption acting like a namespace for the |
counter value.|
|
The counter encryption key is a hash over an account information file |
"$INFO_FILE" which will also be stored in the application data directory.|
|
This file contains the following information as separate lines:|
|
* Fully-qualified host name|
* user name|
* current date/time|
* counter obfuscation password.|
|
This information file will only be created once and then be reused for |
creating all future nonces. It will also be reused partially (except for the |
date/time) when a new temporary counter needs to be created (if |
"$COUNTER_FILE" is not writable).|
|
The obfuscation password is not necessary for safe encryption itself, but |
without it an attacker might be able to derive the following information from |
a nonce: Which account was used to encrypt the message and how many messages |
have already been encrypted using the same counter.|
|
As this information is somewhat sensitive but not relevant for the actual |
decryption, a low-quality obfuscation password will be created automatically |
for the first counter initialization.|
|
This password is created by hashing the following information:|
|
* 32 bytes of low-quality random numbers drawn from /dev/urandom.|
|
* The output of "ps -Af".|
|
* The output of "df -P".|
|
* If the "haveged" executable has been installed, 32 bytes of high-quality |
random numbers created by invoking that utility.|
|
* If /dev/hwrng exists as a character device and is readable, read 32 bytes |
from that device also. A hardware random number generator is frequently made |
available using this pathname.|
|
When using $APP in an initramfs or in a read-only environment (such as "/" |
being mounted from a CD-ROM), it is recommended to not include a copy of the |
"$APP_NAME-$APP_UUID"-directory there.|
|
This will ensure that a new temporary "$INFO_FILE" will be created for every |
use, making it very unlikely that the same nonce will ever be created again.|
|
It is not as good as keeping a writable persistent "$COUNTER_FILE" around |
which will guarantee that a nonce will never be repeated. But it is nearly as |
good.|
|
Also note that new nonces are only required for encryption. Decryption neither |
uses nor requires "$INFO_FILE" or "$COUNTER_FILE".|
===
}
APP=${0##*/}
APP_NAME=simplecrypt
APP_UUID=0xkku1x9jipyr5bsx7itpi64a
COUNTER_FILE=nonce_counter.txt
INFO_FILE=account_info.txt

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

while getopts hV opt
do
	case $opt in
		h) exit_help;;
		V) exit_version;;
		*) false || exit
	esac
done
shift `expr $OPTIND - 1 || :`

encrypt() {
	:
}

decrypt() {
	:
}

case $# in
	1) encrypt "$@";;
	2) decrypt "$@";;
	*) exit_help `false || echo $?` >& 2
esac

exit
xargs printf ' \\\\0%03o' | xargs printf '%b'
