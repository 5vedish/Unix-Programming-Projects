CC = gcc

CFLAGS = -g -Wall -Wextra -Werror -I include/
LDFLAGS = -lcrypto

TARGET = fenc
.PHONY = all clean tests
VPATH = include/

all: $(TARGET) 

$(TARGET): fenc.o func.o
	$(CC) $(CFLAGS) -o $(TARGET) fenc.o func.o $(LDFLAGS)

fenc.o: options.h debug_macros.h src/fenc.c 
	$(CC) $(CFLAGS) $(LDFLAGS) -c src/fenc.c -o fenc.o

func.o: options.h debug_macros.h src/func.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c src/func.c -o func.o

clean: 
	rm -f $(TARGET) *.o

tests: clean all 
	./test1.sh
	./test2.sh
	./test3.sh