rc4sxs-crypt: rc4sxs-crypt.o $(LIBS)
	$(CC) $(LDFLAGS) -o $@ rc4sxs-crypt.o $(LIBS)
treyfer-cfb-512: treyfer-cfb-512.o $(LIBS)
	$(CC) $(LDFLAGS) -o $@ treyfer-cfb-512.o $(LIBS)
treyfer-hash: treyfer-hash.o $(LIBS)
	$(CC) $(LDFLAGS) -o $@ treyfer-hash.o $(LIBS)
treyfer-ofb: treyfer-ofb.o $(LIBS)
	$(CC) $(LDFLAGS) -o $@ treyfer-ofb.o $(LIBS)
