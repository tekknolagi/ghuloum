all: main
	./main

entry.s: compiler.py
	python3 compiler.py

entry.o: entry.s
	nasm -f elf64 entry.s -o entry.o

driver.o: driver.c
	gcc -c driver.c -o driver.o

main: driver.o entry.o
	gcc driver.o entry.o -o main
