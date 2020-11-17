#! /bin/sh

set -e
cleanup() {
	rc=$?
	test "$tf" && rm -- "$tf"
	test $rc = 0 || echo "\"$0\": $error" >& 2
}
error="Failed!"
tf=
trap cleanup 0
trap 'exit $?' INT HUP QUIT TERM

die() {
	case $# in
		0) ;;
		*) error="$*"
	esac
	false || exit
}

write() {
	printf %s "$*"
}

tf=`mktemp -- "${TMPDIR:-/tmp}/${0##*/}.XXXXXXXXXX"`
while read hash encr string
do
	write "$string" | ./rc4hash | cut -c 21-30 > "$tf"
	read h < "$tf"
	case $h in
		"$hash") ;;
		*)
			die \
				"String >>>$string<<< should result in" \
				"digest $hash but instead the following" \
				"digest was generated: $h"
	esac
	e=`write "$string" | ./rc4sxs-crypt -e -- "$tf" | openssl base64`
	case $e in
		"$encr") ;;
		*)
			die \
				"The base-64 encoded encryption of" \
				">>>$string<<< should should be" \
				">>>$encr<<< but instead the following" \
				"digest was the result: >>>$e<<<"
	esac
	continue
	d= `write "$e" | openssl base64 -d | ./rc4sxs-crypt -d -- "$tf"`
	case $d in
		"$string") ;;
		*)
			die \
				"The decryption of base-64 encoded" \
				">>>$e<<< should should be" \
				">>>$string<<< but instead the following" \
				"was the result: >>>$d<<<!"
	esac
done << 'EOF'
X5XYQLVPJN
FY7RDRYASQ 4vcsFA== test
9STLCUF3BS CTAuB7jml5OMeCAW hello, world
5JKGCYYFHR c1dCuMhz3voXijD3Y2zw+4Cp ARCFOUR-based hash
EOF
echo "Successful!"
