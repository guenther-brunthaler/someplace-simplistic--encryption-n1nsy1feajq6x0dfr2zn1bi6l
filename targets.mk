rc4hash: rc4hash.o $(LIBS)
	$(CC) $(LDFLAGS) -o $@ rc4hash.o $(LIBS)
rc4sxs-crypt: rc4sxs-crypt.o $(LIBS)
	$(CC) $(LDFLAGS) -o $@ rc4sxs-crypt.o $(LIBS)
