CFLAGS= -Wall -Wextra -Wl,-z,relro,-z,now
CHAL=race.c
BIN=chal.bin
all: $(CHAL)
	$(CC) -o $(BIN) $(CFLAGS) $(CHAL)
clean: $(BIN)
	rm $(BIN)