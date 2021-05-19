CC = gcc

CFLAGS = -g -Wall -Wextra -Werror -I include/

TARGET = client
.PHONY = all clean tests
VPATH = include/

CFILES = $(wildcard *.c)

all: clean client

client: $(patsubst %.c,%.o,$(CFILES))
	$(CC) $(CFLAGS) -o $@ $^
	
%.d: %.c 
	$(CC) -c $< -MD $@ -I include

%.o: %.c %.d
	$(CC) $(CFLAGS) -c $< -o $@ -I include

clean:
	rm -f $(TARGET) *.o *.d

tests: client
	

