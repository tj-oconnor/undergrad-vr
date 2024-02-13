CFLAGS = -no-pie -fstack-protector-all 
CHAL   = fsop-playground
SRC    = $(CHAL).c
BIN    = $(CHAL).bin
LIBC   = libc.so.6

example:
	gcc -o $(BIN) $(SRC) $(CFLAGS)
	pwninit --bin=$(BIN) --libc=$(LIBC) --no-template


clean:
	rm -rf $(BIN)
