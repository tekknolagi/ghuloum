#!/usr/bin/env python3.6

# http://scheme2006.cs.uchicago.edu/11-ghuloum.pdf


def emit(stream, text):
    stream.write(f"{text}\n")


FIXNUM_SHIFT = 2
FIXNUM_MASK = 0x3
CHAR_SHIFT = 8
CHAR_TAG = 0b00001111
BOOL_SHIFT = 7
BOOL_TAG = 0b0011111
BOOL_MASK = 0b1111111
NIL_TAG = 0b00101111
WORD_SIZE = 4


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
    return isinstance(x, list) and x[0] in PRIMITIVE_TABLE


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


def prim_zerop(stream, arg):
    compile_expr(stream, arg)
    emit(stream, f"cmp eax, 0")
    emit(stream, f"mov eax, 0")
    emit(stream, f"sete al")
    emit(stream, f"shl eax, {BOOL_SHIFT}")
    emit(stream, f"or eax, {BOOL_TAG}")


def prim_nullp(stream, arg):
    compile_expr(stream, arg)
    emit(stream, f"cmp eax, {NIL_TAG}")
    emit(stream, f"mov eax, 0")
    emit(stream, f"sete al")
    emit(stream, f"shl eax, {BOOL_SHIFT}")
    emit(stream, f"or eax, {BOOL_TAG}")


def prim_not(stream, arg):
    compile_expr(stream, arg)
    emit(stream, f"xor eax, {BOOL_TAG}")
    emit(stream, f"mov eax, 0")
    emit(stream, f"sete al")
    emit(stream, f"shl eax, {BOOL_SHIFT}")
    emit(stream, f"or eax, {BOOL_TAG}")


def prim_integerp(stream, arg):
    compile_expr(stream, arg)
    emit(stream, f"and eax, {FIXNUM_MASK}")
    emit(stream, f"cmp eax, 0")
    emit(stream, f"mov eax, 0")
    emit(stream, f"sete al")
    emit(stream, f"shl eax, {BOOL_SHIFT}")
    emit(stream, f"or eax, {BOOL_TAG}")


def prim_booleanp(stream, arg):
    compile_expr(stream, arg)
    emit(stream, f"and eax, {BOOL_MASK}")
    emit(stream, f"cmp eax, {BOOL_TAG}")
    emit(stream, f"mov eax, 0")
    emit(stream, f"sete al")
    emit(stream, f"shl eax, {BOOL_SHIFT}")
    emit(stream, f"or eax, {BOOL_TAG}")


def prim_binplus(stream, left, right, si):
    compile_expr(stream, right, si)
    emit(stream, f"mov [rsp-{si}], eax")
    compile_expr(stream, left, si + WORD_SIZE)
    emit(stream, f"add eax, [rsp-{si}]")


prim_binplus.stack_index = True


def prim_binminus(stream, left, right, si):
    compile_expr(stream, right, si)
    emit(stream, f"mov [rsp-{si}], eax")
    compile_expr(stream, left, si + WORD_SIZE)
    emit(stream, f"sub eax, [rsp-{si}]")


prim_binminus.stack_index = True


PRIMITIVE_TABLE = {
    "add1": prim_add1,
    "sub1": prim_sub1,
    "integer->char": prim_int_to_char,
    "char->integer": prim_char_to_int,
    "zero?": prim_zerop,
    "null?": prim_nullp,
    "not": prim_not,
    "integer?": prim_integerp,
    "boolean?": prim_booleanp,
    "+": prim_binplus,
    "-": prim_binminus,
}


def emit_primcall(stream, x, si):
    op, *args = x
    fn = PRIMITIVE_TABLE[op]
    if getattr(fn, "stack_index", False):
        fn(stream, *args, si)
    else:
        fn(stream, *args)


def compile_expr(stream, x, si):
    if is_immediate(x):
        mov(stream, "eax", imm(x))
        return
    elif is_primcall(x):
        emit_primcall(stream, x, si)
        return
    raise ValueError(x)


def compile_program(stream, x):
    emit(
        stream,
        """section .text
global scheme_entry
scheme_entry:""",
    )
    compile_expr(stream, x, si=WORD_SIZE)
    emit(stream, "ret")


if __name__ == "__main__":
    with open("entry.s", "w") as f:
        compile_program(f, ["-", 5, 2])
