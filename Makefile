all: main

entry.s: compiler.py
	python3 compiler.py

entry.o: entry.s
	nasm -f macho64 entry.s -o entry.o

driver.o: driver.c
	gcc -c driver.c -o driver.o

main: driver.o entry.o
	ld -macosx_version_min 10.14 -lSystem -arch x86_64 -o main driver.o entry.o
