all: compiler
	./compiler

compiler: compiler.c libtap/tap.h libtap/tap.c
	gcc -Wall -Wextra -pedantic -O2 -g compiler.c libtap/tap.c -o compiler

entry.s: compiler.py
	python3 compiler.py

entry.o: entry.s
	nasm -f macho64 entry.s -o entry.o

driver.o: driver.c
	gcc -c driver.c -o driver.o

main: driver.o entry.o
	ld -macosx_version_min 10.14 -lSystem -arch x86_64 -o main driver.o entry.o
