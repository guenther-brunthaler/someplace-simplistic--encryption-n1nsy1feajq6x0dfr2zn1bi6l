.POSIX:

TARGETS = mdarc4
DOCS = README.html

CFLAGS = -D NDEBUG -O
LDFLAGS = -s

.PHONY: all clean doc

all: $(TARGETS)

doc: $(DOCS)

$(DOCS): $(DOCS:.html=.adoc)
	asciidoc $?

clean:
	-rm $(TARGETS) $(DOCS)
