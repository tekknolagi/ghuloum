#!/usr/bin/python3.6
import io
import unittest
import sexpdata
import sys


def to_dcsexp(stream, sexp):
    if isinstance(sexp, list):
        if not sexp:
            stream.write("Z0:")  # nil
            return
        stream.write(".")
        to_dcsexp(stream, sexp[0])
        to_dcsexp(stream, sexp[1:])
        return
    if isinstance(sexp, sexpdata.Symbol):
        value = sexp.value()
        stream.write(f"Y{len(value)}:{value}")
        return
    if isinstance(sexp, sexpdata.String):
        value = sexp.value()
        stream.write(f"S{len(value)}:{value}")
        return
    if isinstance(sexp, bool):
        stream.write(f"B1:{'t' if sexp else 'f'}")
        return
    if isinstance(sexp, int):
        length = len(str(sexp))
        stream.write(f"N{length}:{sexp}")
        return
    raise ValueError("not valid sexp")


def string_of_dcsexp(sexp):
    stream = io.StringIO()
    to_dcsexp(stream, sexp)
    return stream.getvalue()


if __name__ == "__main__":
    sexp = sexpdata.load(sys.stdin, true="#t", false="#f")
    to_dcsexp(sys.stdout, sexp)
    print(file=sys.stdout)
