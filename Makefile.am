bin_PROGRAMS = chacha20
chacha20_SOURCES = chacha20.c cc20_struct.h
EXTRA_DIST = autogen.sh sdef2h cc20.sdef

cc20_struct.h: cc20.sdef
	$(top_srcdir)/sdef2h < $< > $@
