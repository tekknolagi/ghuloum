all: compiler
	./compiler

compiler: compiler.c libtap/tap.h libtap/tap.c
	gcc -Wall -Wextra -pedantic -Werror=incompatible-pointer-types -O0 -g -std=c99 \
		compiler.c libtap/tap.c -o compiler
