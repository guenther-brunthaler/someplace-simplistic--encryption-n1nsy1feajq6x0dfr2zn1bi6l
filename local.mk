LOCALLY_GENERATED = $(DOCS) config.h

DOCS = README.html

doc: $(DOCS)

$(DOCS): $(DOCS:.html=.adoc)
	asciidoc $?

config.h:
	case `uname -o` in \
		*GNU*) echo '#define _FILE_OFFSET_BITS 64'; \
	esac > $@
