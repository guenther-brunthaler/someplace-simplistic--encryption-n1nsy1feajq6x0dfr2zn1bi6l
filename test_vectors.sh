#! /bin/sh
while read hash string
do
	h=`printf '%s' "\$string" | ./rc4hash`
	test "$h" = "$hash" && continue
	{
		echo "String >>>$string<<< should result in digest"
		echo "$hash but instead the following digest was generated:"
		echo "$h"
	} >& 2
	false || exit
done << 'EOF'
L7APSJFWRQE57TUHH7YUX5XYQLVPJNKNHQD6FACZKFMBV8JNAQ2Z
45JAG6GDGPENNJCD276ZFY7RDRYASQTJDDW998C59AUEDVCKGE2E test
BKYQ53HW53DP323KCUA49STLCUF3BSZ8HE9BJYXKXCF96CWX5AF5 hello, world
D7UESP8ER2S8XZZK4ACL5JKGCYYFHR5C6BBRXL92QD3HKBK9U8G7 ARCFOUR-based hash
EOF
echo "Successful!"
