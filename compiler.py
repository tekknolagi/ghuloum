#!/usr/bin/env python3.6

# http://scheme2006.cs.uchicago.edu/11-ghuloum.pdf


def emit(stream, text):
    stream.write(f"{text}\n")


FIXNUM_SHIFT = 2
CHAR_SHIFT = 8
CHAR_TAG = 0b00001111
BOOL_SHIFT = 7
BOOL_TAG = 0b0011111
NIL_TAG = 0b00101111


def is_immediate(x):
    return isinstance(x, (bool, int, str)) or x == []


def imm(x):
    if not is_immediate(x):
        raise ValueError(x)
    if isinstance(x, bool):
        return (x << BOOL_SHIFT) | BOOL_TAG
    if isinstance(x, int):
        return x << FIXNUM_SHIFT
    if isinstance(x, str):
        c = ord(x)
        return (c << CHAR_SHIFT) | CHAR_TAG
    if isinstance(x, list):
        assert x == []
        return NIL_TAG


def mov(stream, dst, val):
    emit(stream, f"mov {dst}, {val}")


def is_primcall(x):
    return isinstance(x, list) and len(x) == 2 and isinstance(x[0], str)


def prim_add1(stream, arg):
    compile_expr(stream, arg)
    emit(stream, f"add eax, {imm(1)}")


def prim_sub1(stream, arg):
    compile_expr(stream, arg)
    emit(stream, f"sub eax, {imm(1)}")


def prim_int_to_char(stream, arg):
    compile_expr(stream, arg)
    # ints are already "shifted" 2 over
    emit(stream, f"shl eax, 6")
    emit(stream, f"add eax, {CHAR_TAG}")


def prim_char_to_int(stream, arg):
    compile_expr(stream, arg)
    # ints should have 2 trailing zeroes
    emit(stream, f"shr eax, 6")


def compile_expr(stream, x):
    if is_immediate(x):
        mov(stream, "eax", imm(x))
        return
    elif is_primcall(x):
        op, arg1, *args = x
        table = {
            "add1": prim_add1,
            "sub1": prim_sub1,
            "integer->char": prim_int_to_char,
            "char->integer": prim_char_to_int,
        }
        table[op](stream, arg1)
        return
    raise ValueError(x)


def compile_program(stream, x):
    emit(
        stream,
        """section .text
global _scheme_entry
_scheme_entry:""",
    )
    compile_expr(stream, x)
    emit(stream, "ret")


if __name__ == "__main__":
    with open("entry.s", "w") as f:
        compile_program(f, ["integer->char", 65])
