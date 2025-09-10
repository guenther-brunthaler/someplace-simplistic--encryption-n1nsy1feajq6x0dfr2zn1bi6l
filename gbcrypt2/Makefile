.POSIX:

.PHONY: all clean

TARGETS = gbcrypt2.standalone

all: $(TARGETS)

clean:
	-rm $(TARGETS)

GBCRYPT2_BUDDIES = gbcrypt2 \
	dec2raw key2prand psw2key raw2dec rc4csprng10 xor10

gbcrypt2.standalone: amalgamation $(GBCRYPT2_BUDDIES)
	@echo Generating $@
	@phase=searching; \
	while IFS= read -r line; \
	do \
		case $$phase:$$line in \
			searching:---snip---) phase=insert;; \
			insert:---snip---) \
				for f in $(GBCRYPT2_BUDDIES); \
				do \
					wc -c $$f; cat $$f; \
				done; \
				phase=copy_rest; \
		esac; \
		printf '%s\n' "$$line"; \
	done < amalgamation > $@; \
	chmod +x $@
