.POSIX:

# Preset portable default build options. Override by either assigning some of
# those directly as part of the "make" command-line arguments. Or export
# environment variables of the same names, plus "export MAKEFLAGS=e" also.
CPPFLAGS = -D NDEBUG
CFLAGS = -O
LDFLAGS = -s

OBJECTS = $(SOURCES:.c=.o)
TARGETS = $(OBJECTS:.o=)
DOCS = README.html
LIBS = $(LIB_1_SUBDIR)/lib$(LIB_1_SUBDIR).a

LIB_1_SUBDIR =  fragments
LIB_1_INC_SUBDIR = include

.PHONY: all clean

include sources.mk

all: $(TARGETS)

clean:
	-cd $(LIB_1_SUBDIR) && $(MAKE) clean
	-rm $(TARGETS) $(OBJECTS) $(DOCS)

doc: $(DOCS)

$(DOCS): $(DOCS:.html=.adoc)
	asciidoc $?

COMBINED_CFLAGS= $(CPPFLAGS) $(CFLAGS)
AUG_CFLAGS = \
	$(COMBINED_CFLAGS) \
	-I . \
	-I $(LIB_1_SUBDIR)/$(LIB_1_INC_SUBDIR)

.c.o:
	$(CC) $(AUG_CFLAGS) -c $<

include dependencies.mk
include targets.mk

$(LIBS):
	for lib in $@; do (cd "`dirname "$$lib"`" && $(MAKE)); done

include maintainer.mk # Rules not required for just building the application.
