CC = gcc

CFLAGS = -g -Wall -Wextra -Werror -I include/
GLIBPKG = $(shell pkg-config --cflags --libs gmodule-2.0)
LDFLAGS = -l lkmalloc -L .

TARGET = lkmalloc
.PHONY = all clean tests
VPATH = include/

all: clean main malloc_mem realloc_mem malloc_exist malloc_free free_wout_approx middle_free_warn free_no_malloc free_error double_free double_middle_free realloc_larger realloc_smaller realloc_null mem_leak mem_leak_over

main: main.o liblkmalloc.a
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(GLIBPKG)

main.o: headers.h src/main.c
	$(CC) $(CFLAGS) -c src/main.c -o main.o

lkmalloc.o: headers.h src/lkmalloc.c
	$(CC) $(CFLAGS) -c src/lkmalloc.c -o lkmalloc.o $(GLIBPKG)

liblkmalloc.a: lkmalloc.o
	ar rcs liblkmalloc.a lkmalloc.o

malloc_mem: malloc_mem.o liblkmalloc.a # Test 1
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(GLIBPKG)

malloc_mem.o: headers.h src/malloc_mem.c
	$(CC) $(CFLAGS) -c src/malloc_mem.c -o malloc_mem.o

realloc_mem: realloc_mem.o liblkmalloc.a # Test 2
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(GLIBPKG)

realloc_mem.o: headers.h src/realloc_mem.c
	$(CC) $(CFLAGS) -c src/realloc_mem.c -o realloc_mem.o

malloc_exist: malloc_exist.o liblkmalloc.a # Test 3
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(GLIBPKG)

malloc_exist.o: headers.h src/malloc_exist.c
	$(CC) $(CFLAGS) -c src/malloc_exist.c -o malloc_exist.o

malloc_free: malloc_free.o liblkmalloc.a # Test 4
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(GLIBPKG)

malloc_free.o: headers.h src/malloc_free.c
	$(CC) $(CFLAGS) -c src/malloc_free.c -o malloc_free.o

free_wout_approx: free_wout_approx.o liblkmalloc.a # Test 4
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(GLIBPKG)

free_wout_approx.o: headers.h src/free_wout_approx.c
	$(CC) $(CFLAGS) -c src/free_wout_approx.c -o free_wout_approx.o

middle_free_warn: middle_free_warn.o liblkmalloc.a # Test 4
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(GLIBPKG)

middle_free_warn.o: headers.h src/middle_free_warn.c
	$(CC) $(CFLAGS) -c src/middle_free_warn.c -o middle_free_warn.o

free_no_malloc: free_no_malloc.o liblkmalloc.a # Test 4
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(GLIBPKG)

free_no_malloc.o: headers.h src/free_no_malloc.c
	$(CC) $(CFLAGS) -c src/free_no_malloc.c -o free_no_malloc.o

free_error: free_error.o liblkmalloc.a # Test 4
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(GLIBPKG)

free_error.o: headers.h src/free_error.c
	$(CC) $(CFLAGS) -c src/free_error.c -o free_error.o

double_free: double_free.o liblkmalloc.a # Test 4
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(GLIBPKG)

double_free.o: headers.h src/double_free.c
	$(CC) $(CFLAGS) -c src/double_free.c -o double_free.o

double_middle_free: double_middle_free.o liblkmalloc.a # Test 4
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(GLIBPKG)

double_middle_free.o: headers.h src/double_middle_free.c
	$(CC) $(CFLAGS) -c src/double_middle_free.c -o double_middle_free.o

realloc_larger: realloc_larger.o liblkmalloc.a # Test 4
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(GLIBPKG)

realloc_larger.o: headers.h src/realloc_larger.c
	$(CC) $(CFLAGS) -c src/realloc_larger.c -o realloc_larger.o

realloc_smaller: realloc_smaller.o liblkmalloc.a # Test 4
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(GLIBPKG)

realloc_smaller.o: headers.h src/realloc_smaller.c
	$(CC) $(CFLAGS) -c src/realloc_smaller.c -o realloc_smaller.o

realloc_null: realloc_null.o liblkmalloc.a # Test 4
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(GLIBPKG)

realloc_null.o: headers.h src/realloc_null.c
	$(CC) $(CFLAGS) -c src/realloc_null.c -o realloc_null.o

mem_leak: mem_leak.o liblkmalloc.a # Test 4
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(GLIBPKG)

mem_leak.o: headers.h src/mem_leak.c
	$(CC) $(CFLAGS) -c src/mem_leak.c -o mem_leak.o

mem_leak_over: mem_leak.o liblkmalloc.a # Test 4
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(GLIBPKG)

mem_leak_over.o: headers.h src/mem_leak_over.c
	$(CC) $(CFLAGS) -c src/mem_leak_over.c -o mem_leak_over.o

clean: 
	rm -f $(TARGET) *.o

tests: clean all 
	./test1.sh
	./test2.sh
	./test3.sh
	./test4.sh
	./test5.sh
	./test6.sh
	./test7.sh
	./test8.sh
	./test9.sh
	./test10.sh
	./test11.sh
	./test12.sh
	./test13.sh
	./test14.sh
	./test15.sh