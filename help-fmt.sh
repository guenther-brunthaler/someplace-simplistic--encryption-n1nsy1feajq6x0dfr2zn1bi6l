exit_help() {
	help | sed 's/ |$/ /; s/|\(.\)/_QQQ_\1/g' | tr -d '\n' | tr '|' '\n' \
	| sed 's/_QQQ_/|/g' | show
	echo; exit_version "$@"
}
