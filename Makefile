CC = gcc
CFLAGS = -Wall -Werror -Wextra -O0 -ggdb
OBJ = main.o xdns.o 

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

xdns: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean
clean:
	@rm -f *.o
	@rm -f xdns
