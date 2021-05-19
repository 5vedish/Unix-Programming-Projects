CC = gcc

CFLAGS = -g -Wall -Wextra -Werror -D EXTRA_CREDIT=1 -I include/

TARGET = tish
.PHONY = all clean tests
VPATH = include/

CFILES = $(wildcard *.c)

all: clean tish

tish: $(patsubst %.c,%.o,$(CFILES))
	$(CC) $(CFLAGS) -o $@ $^ 
	
%.d: %.c 
	$(CC) -c $< -MD $@ -I include

%.o: %.c %.d
	$(CC) $(CFLAGS) -c $< -o $@ -I include

clean:
	rm -f $(TARGET) *.o *.d

tests: tish
	./test1.sh
	./test2.sh
	./test3.sh
	./test4.sh

