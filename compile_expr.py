#!/usr/bin/env python3.6
import sys
import sexpdata
from compiler import HEAP_PTR, WORD_SIZE, Compiler


if __name__ == "__main__":
    with open(sys.argv[1], "r") as infile:
        sexp = sexpdata.load(infile, true="#t", false="#f")

    with open(sys.argv[2], "w") as outfile:
        c = Compiler(outfile)
        c.emit(
            f"""section .text
    global scheme_entry
    scheme_entry:
    mov {HEAP_PTR}, rdi"""
        )
        c.visit_exp(sexp, WORD_SIZE, {})
        c.emit("ret")
