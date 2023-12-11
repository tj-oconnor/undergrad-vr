SP      = -fstack-protector-all
PIE     = -pie
NPIE    = -no-pie
NORELRO = -Wl,-z,norelro
FURELRO = -Wl,-z,relro,-z,now
CHAL   = oob
SRC    = $(CHAL).c
BIN    = $(CHAL)-nopie.bin
PBIN   = $(CHAL)-pie.bin
FBIN   = $(CHAL)-relro.bin


example:
	gcc -o $(BIN) $(SRC) $(SP) $(NPIE)

pie:
	gcc -o $(PBIN) $(SRC) $(SP) $(PIE)

full-relro:
	gcc -o $(FBIN) $(SRC) $(SP) $(PIE) $(FURELRO)

clean:
	rm -rf $(BIN)
