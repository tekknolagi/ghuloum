all: compiler
	./compiler

compiler: compiler.c libtap/tap.h libtap/tap.c
	gcc -Wall -Wextra -pedantic -O0 -g -std=c99 compiler.c libtap/tap.c -o compiler
