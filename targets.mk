rc4sxs-crypt: rc4sxs-crypt.o $(LIBS)
	$(CC) $(LDFLAGS) -o $@ rc4sxs-crypt.o $(LIBS)
treyfer-ofb: treyfer-ofb.o $(LIBS)
	$(CC) $(LDFLAGS) -o $@ treyfer-ofb.o $(LIBS)
