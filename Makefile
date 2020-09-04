all: compiler
	./compiler

test: compiler
	./compiler

compiler: compiler.c libtap/tap.h libtap/tap.c
	gcc -Wall -Wextra -pedantic -O0 -g -std=c99 -o compiler \
		-Werror=incompatible-pointer-types -Werror=unused-function \
		compiler.c libtap/tap.c
