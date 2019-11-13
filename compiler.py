#!/usr/bin/env python3.6

# http://scheme2006.cs.uchicago.edu/11-ghuloum.pdf


import sexpdata
import sys


FIXNUM_SHIFT = 2
FIXNUM_MASK = 0x3
CHAR_SHIFT = 8
CHAR_TAG = 0b00001111
BOOL_SHIFT = 7
BOOL_TAG = 0b0011111
BOOL_MASK = 0b1111111
NIL_TAG = 0b00101111
PAIR_TAG = 0b1
WORD_SIZE = 8
PAIR_SIZE = WORD_SIZE * 2
HEAP_PTR = "rsi"


def is_immediate(x):
    return isinstance(x, (bool, int, str)) or x == []


def imm_int(x):
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


def imm(x):
    return hex(imm_int(x))


def is_primcall(x):
    return (
        isinstance(x, list)
        and len(x) >= 2
        and isinstance(x[0], sexpdata.Symbol)
        and x[0].value() in PRIMITIVE_TABLE
    )


def prim_add1(compiler, arg, stack_index, env):
    compiler.visit_exp(arg, stack_index, env)
    compiler.emit(f"add rax, {imm(1)}")


def prim_sub1(compiler, arg, stack_index, env):
    compiler.visit_exp(arg, stack_index, env)
    compiler.emit(f"sub rax, {imm(1)}")


def prim_int_to_char(compiler, arg, stack_index, env):
    compiler.visit_exp(arg, stack_index, env)
    # ints are already "shifted" 2 over
    compiler.emit(f"shl rax, 6")
    compiler.emit(f"add rax, {CHAR_TAG}")


def prim_char_to_int(compiler, arg, stack_index, env):
    compiler.visit_exp(arg, stack_index, env)
    # ints should have 2 trailing zeroes
    compiler.emit(f"shr rax, 6")


def prim_zerop(compiler, arg, stack_index, env):
    compiler.visit_exp(arg, stack_index, env)
    compiler.emit(f"cmp rax, 0")
    compiler.emit(f"mov rax, 0")
    compiler.emit(f"sete al")
    compiler.emit(f"shl rax, {BOOL_SHIFT}")
    compiler.emit(f"or rax, {BOOL_TAG}")


def prim_nullp(compiler, arg, stack_index, env):
    compiler.visit_exp(arg, stack_index, env)
    compiler.emit(f"cmp rax, {NIL_TAG}")
    compiler.emit(f"mov rax, 0")
    compiler.emit(f"sete al")
    compiler.emit(f"shl rax, {BOOL_SHIFT}")
    compiler.emit(f"or rax, {BOOL_TAG}")


def prim_not(compiler, arg, stack_index, env):
    compiler.visit_exp(arg, stack_index, env)
    compiler.emit(f"xor rax, {BOOL_TAG}")
    compiler.emit(f"mov rax, 0")
    compiler.emit(f"sete al")
    compiler.emit(f"shl rax, {BOOL_SHIFT}")
    compiler.emit(f"or rax, {BOOL_TAG}")


def prim_integerp(compiler, arg, stack_index, env):
    compiler.visit_exp(arg, stack_index, env)
    compiler.emit(f"and rax, {FIXNUM_MASK}")
    compiler.emit(f"cmp rax, 0")
    compiler.emit(f"mov rax, 0")
    compiler.emit(f"sete al")
    compiler.emit(f"shl rax, {BOOL_SHIFT}")
    compiler.emit(f"or rax, {BOOL_TAG}")


def prim_booleanp(compiler, arg, stack_index, env):
    compiler.visit_exp(arg, stack_index, env)
    compiler.emit(f"and rax, {BOOL_MASK}")
    compiler.emit(f"cmp rax, {BOOL_TAG}")
    compiler.emit(f"mov rax, 0")
    compiler.emit(f"sete al")
    compiler.emit(f"shl rax, {BOOL_SHIFT}")
    compiler.emit(f"or rax, {BOOL_TAG}")


def prim_binplus(compiler, left, right, stack_index, env):
    compiler.visit_exp(right, stack_index, env)
    compiler.emit(f"mov [rsp-{stack_index}], rax")
    compiler.visit_exp(left, stack_index + WORD_SIZE, env)
    compiler.emit(f"add rax, [rsp-{stack_index}]")


def prim_binminus(compiler, left, right, stack_index, env):
    compiler.visit_exp(right, stack_index, env)
    compiler.emit(f"mov [rsp-{stack_index}], rax")
    compiler.visit_exp(left, stack_index + WORD_SIZE, env)
    compiler.emit(f"sub rax, [rsp-{stack_index}]")


def prim_binmul(compiler, left, right, stack_index, env):
    compiler.visit_exp(right, stack_index, env)
    compiler.emit(f"mov [rsp-{stack_index}], rax")
    compiler.visit_exp(left, stack_index + WORD_SIZE, env)
    # can't just multiply encoded ints due to tag
    compiler.emit(f"shr qword [rsp-{stack_index}], {FIXNUM_SHIFT}")
    compiler.emit(f"mul qword [rsp-{stack_index}]")


def prim_cons(compiler, car, cdr, stack_index, env):
    compiler.visit_exp(car, stack_index, env)
    compiler.emit(f"mov [{HEAP_PTR}], rax")
    compiler.visit_exp(cdr, stack_index, env)
    compiler.emit(f"mov [{HEAP_PTR}+{WORD_SIZE}], rax")
    compiler.emit(f"mov rax, {HEAP_PTR}")
    compiler.emit(f"or rax, {PAIR_TAG}")
    compiler.emit(f"add {HEAP_PTR}, {PAIR_SIZE}")


def prim_car(compiler, expr, stack_index, env):
    compiler.visit_exp(expr, stack_index, env)
    compiler.emit(f"mov rax, [rax-{PAIR_TAG}]")


def prim_cdr(compiler, expr, stack_index, env):
    compiler.visit_exp(expr, stack_index, env)
    compiler.emit(f"mov rax, [rax+{WORD_SIZE-PAIR_TAG}]")


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
    "*": prim_binmul,
    "cons": prim_cons,
    "car": prim_car,
    "cdr": prim_cdr,
}


def is_let(x):
    return (
        isinstance(x, list)
        and len(x) == 3
        and isinstance(x[0], sexpdata.Symbol)
        and x[0].value() == "let"
    )


def is_if(x):
    return (
        isinstance(x, list)
        and len(x) == 4
        and isinstance(x[0], sexpdata.Symbol)
        and x[0].value() == "if"
    )


def is_code(x):
    return isinstance(x, list) and len(x) == 3 and x[0].value() == "code"


def is_labels(x):
    return isinstance(x, list) and len(x) == 3 and x[0].value() == "labels"


def is_labelcall(x):
    return isinstance(x, list) and len(x) >= 2 and x[0].value() == "labelcall"


class Compiler:
    def __init__(self, stream):
        self.stream = stream
        self.last_label = -1

    def _unique_label(self):
        self.last_label += 1
        return f"L{self.last_label}"

    def emit(self, text):
        self.stream.write(f"{text}\n")

    def emit_label(self, label):
        self.emit(f"{label}:")

    def visit_primcall(self, node, stack_index, env):
        op, *args = node
        fn = PRIMITIVE_TABLE[op.value()]
        fn(self, *args, stack_index, env)

    def visit_let(self, bindings, body, stack_index, env):
        if not bindings:
            self.visit_exp(body, stack_index, env)
            return
        new_env = env.copy()
        name, expr = bindings[0]
        self.visit_exp(expr, stack_index, env)
        self.emit(f"mov [rsp-{stack_index}], rax")
        new_env[name.value()] = stack_index
        self.visit_let(bindings[1:], body, stack_index + WORD_SIZE, new_env)

    def visit_if(self, cond, consequent, alternative, stack_index, env):
        L0 = self._unique_label()
        L1 = self._unique_label()
        self.visit_exp(cond, stack_index, env)
        self.emit(f"cmp rax, {imm(False)}")
        self.emit(f"je {L0}")
        self.visit_exp(consequent, stack_index, env)
        self.emit(f"jmp {L1}")
        self.emit_label(L0)
        self.visit_exp(alternative, stack_index, env)
        self.emit_label(L1)

    def visit_code(self, formals, body, stack_index, env):
        new_env = env.copy()
        body_si = 0
        for formal in formals:
            body_si += WORD_SIZE
            new_env[formal.value()] = body_si
        self.visit_exp(body, body_si, new_env)
        self.emit("ret")

    def visit_labels(self, labels, body, stack_index, env):
        new_env = env.copy()
        body_label = self._unique_label()
        self.emit(f"jmp {body_label}")
        for given_label, lexp in labels:
            label = self._unique_label()
            new_env[given_label.value()] = label
            self.emit_label(label)
            self.visit_exp(lexp, stack_index, new_env)
        self.emit_label(body_label)
        self.visit_exp(body, stack_index, new_env)

    def visit_labelcall(self, lvar, args, stack_index, env):
        for arg in args:
            stack_index += WORD_SIZE
            self.visit_exp(arg, stack_index, env)
            self.emit(f"mov [rsp-{stack_index}], rax")
        self.emit(f"call {env[lvar.value()]}")

    def visit_immediate(self, x):
        self.emit(f"mov rax, {imm(x)}")

    def visit_exp(self, x, stack_index, env):
        if is_immediate(x):
            self.visit_immediate(x)
            return
        elif is_primcall(x):
            self.visit_primcall(x, stack_index, env)
            return
        elif isinstance(x, sexpdata.Symbol):
            offset = env[x.value()]
            self.emit(f"mov rax, [rsp-{offset}]")
            return
        elif is_let(x):
            bindings = x[1]
            body = x[2]
            self.visit_let(*x[1:], stack_index, env)
            return
        elif is_if(x):
            self.visit_if(*x[1:], stack_index, env)
            return
        elif is_labels(x):
            self.visit_labels(*x[1:], stack_index, env)
            return
        elif is_code(x):
            self.visit_code(*x[1:], stack_index, env)
            return
        elif is_labelcall(x):
            self.visit_labelcall(x[1], x[2:], stack_index, env)
            return
        # TODO(emacs): Compile strings (0b011)
        # TODO(emacs): Compile vectors (0b010)
        # TODO(emacs): Compile symbols (0b101)
        # TODO(emacs): Compile closures (0b110)
        raise ValueError(x)

    def compile_program(self, x, env=None):
        self.emit(
            f"""section .text
    global scheme_entry
    scheme_entry:
    mov {HEAP_PTR}, rdi"""
        )
        if env is None:
            env = {}
        self.visit_exp(x, WORD_SIZE, env)
        self.emit("ret")


if __name__ == "__main__":
    with open(sys.argv[1], "r") as infile:
        sexp = sexpdata.load(infile, true="#t", false="#f")

    with open(sys.argv[2], "w") as outfile:
        c = Compiler(outfile)
        c.compile_program(sexp)
