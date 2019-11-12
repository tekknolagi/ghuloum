all:
	@./run_tests.sh

build/%.s: %.in ../compiler.py
	echo "Running test" $*"..."
	python3 ../compiler.py $< $@

build/%.o: %.c
	gcc -c $< -o $@

build/%.o: build/%.s
	nasm -f elf64 $< -o $@

build/%.out: build/%.o build/test_driver.o
	gcc $^ -o $@

%.diff: build/%.out
	./$< > build/$*.output
	diff build/$*.output $*.expected

.PRECIOUS: build/%.o build/%.out
