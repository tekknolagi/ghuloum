test: compiler.py compiler_test.py
	@echo "Running tests..."
	@python3 compiler_test.py
	@make --no-print-directory -C test

.PHONY: test
