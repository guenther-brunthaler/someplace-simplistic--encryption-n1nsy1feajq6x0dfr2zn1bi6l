bin_PROGRAMS = chacha20

EXTRA_DIST = autogen.sh sdef2h cc20.sdef

chacha20_SOURCES = chacha20.c cc20_struct.h

cc20_struct.h: cc20.sdef
	$(top_srcdir)/sdef2h < $< > $@
