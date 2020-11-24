# v2020.329
#
# This makefile snippet includes additional rules which are only required by
# the maintainer of the application, and are of no interest to a user who just
# wants to build the application. Thoses rules have been moved here to keep
# the primary Makefile small.

.PHONY: scan depend depend_helper

scan:
	{ \
		t=`printf '\t:'`; t=$${t%?}; \
		printf 'SOURCES = \\\n'; \
		ls *.c | LC_COLLATE=C sort | { \
			while IFS= read -r src; do \
				printf '%s\n' "$$src"; \
			done; \
		} | sed "s/^/$$t/; "'s/$$/ \\/'; \
		echo; \
	} > sources.mk

depend_helper:
	T1=`mktemp $${TMPDIR:-/tmp}/mkdepend.T1_XXXXXXXXXX`; \
	trap 'rm -- "$$T1"' 0; \
	T2=`mktemp $${TMPDIR:-/tmp}/mkdepend.T2_XXXXXXXXXX`; \
	trap 'rm -- "$$T1" "$$T2"' 0; \
	for o in $(OBJECTS); do \
		$(MAKE) CFLAGS="$(AUG_CFLAGS) -MM -MF $$T1" $$o \
		&& cat $$T1 >& 9; \
	done 9> "$$T2"; \
	awk ' \
		$$1 ~ /:$$/ {t= $$1; $$1= "\\"} \
		{ \
			for (i= 1; i <= NF; ++i) { \
				if ($$i != "\\") print t " " $$i \
			} \
		} \
	' "$$T2" | LC_COLLATE=C sort > $(outfile)

depend: clean scan
	outfile=dependencies.mk; > $$outfile; \
	$(MAKE) outfile="$$outfile" depend_helper
