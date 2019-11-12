#!/usr/bin/env python3.6
import sys
import sexpdata
from compiler import HEAP_PTR, WORD_SIZE, compile_expr, emit


def compile_expr_stub(stream, x):
    emit(
        stream,
        f"""section .text
global scheme_entry
scheme_entry:
mov {HEAP_PTR}, rdi""",
    )
    compile_expr(stream, x, WORD_SIZE, {})
    emit(stream, "ret")


if __name__ == "__main__":
    with open(sys.argv[1], "r") as infile:
        sexp = sexpdata.load(infile, true="#t", false="#f")

    with open(sys.argv[2], "w") as outfile:
        compile_expr_stub(outfile, sexp)
