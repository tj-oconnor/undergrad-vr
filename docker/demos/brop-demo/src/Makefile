CFLAGS = -fno-stack-protector -no-pie -fno-builtin -Wno-all -Wno-extra
CHAL   = ghost
SRC    = $(CHAL).c
BIN    = $(CHAL).bin

example:
	gcc -o $(BIN) $(SRC) $(CFLAGS)

clean:
	rm -rf $(BIN)
