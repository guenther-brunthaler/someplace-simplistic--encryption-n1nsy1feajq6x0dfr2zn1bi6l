#! /bin/sh

# An example how to use rc4dropN for actual encryption/decryption using a
# user-specified long-term password used for several messages and a salt which
# is different for every message.

# Define testing text and password.
cat << '---' > plaintext.txt
This is a test.
---

cat << '---' > psw.txt
my secret pass phrase
---

# Define parameters to use: drop<N>, # key octets, # salt octets
d=3072; keysz=211; saltsz=32

# Encryption
# ----------

dd if=/dev/urandom bs=1 count=$saltsz > salt.bin 2> /dev/null
{
	printf "`printf 'N\\%o' $(($d / 256))`"
	printf "`printf 'Z\\%oK' $(($keysz % 256))`"
	{
		cat salt.bin && tr -d '\n' < psw.txt && cat salt.bin
	} | ./rc4hash -rB $keysz
	printf T
	cat plaintext.txt
} | ./rc4dropN | { cat salt.bin -; rm salt.bin; } > encrypted.bin

# Decryption
# ----------

{
	dd bs=1 count=$saltsz > salt.bin 2> /dev/null
	printf "`printf 'N\\%o' $(($d / 256))`"
	printf "`printf 'Z\\%oK' $(($keysz % 256))`"
	{
		cat salt.bin && tr -d '\n' < psw.txt && cat salt.bin
		rm salt.bin
	} | ./rc4hash -rB $keysz
	printf T
	cat
} < encrypted.bin | ./rc4dropN > decrypted.txt

# Verify decryption.
cmp decrypted.txt plaintext.txt && echo 'Test passed!'
