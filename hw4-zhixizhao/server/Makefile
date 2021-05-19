CC = gcc

CFLAGS = -g -Wall -Wextra -Werror -I include/

TARGET = server
.PHONY = all clean tests
VPATH = include/

CFILES = $(wildcard *.c)

all: clean server

tish: $(patsubst %.c,%.o,$(CFILES))
	$(CC) $(CFLAGS) -o $@ $^ 
	
%.d: %.c 
	$(CC) -c $< -MD $@ -I include

%.o: %.c %.d
	$(CC) $(CFLAGS) -c $< -o $@ -I include

clean:
	rm -f $(TARGET) *.o *.d
	rm -f /tmp/client-server
	rm -f /tmp/server-client

tests: server

