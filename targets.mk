rc4hash: rc4hash.o $(LIBS)
	$(CC) $(LDFLAGS) -o $@ rc4hash.o $(LIBS)
rc4sxs: rc4sxs.o $(LIBS)
	$(CC) $(LDFLAGS) -o $@ rc4sxs.o $(LIBS)
