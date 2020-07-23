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
RAX = "rax"


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


def prim_add1(c, arg, stack_index, env):
    c.visit_exp(arg, stack_index, env)
    c.add(RAX, imm(1))


def prim_sub1(c, arg, stack_index, env):
    c.visit_exp(arg, stack_index, env)
    c.sub(RAX, imm(1))


def prim_int_to_char(c, arg, stack_index, env):
    c.visit_exp(arg, stack_index, env)
    # ints are already "shifted" 2 over
    c.shl(RAX, 6)
    c.add(RAX, CHAR_TAG)


def prim_char_to_int(c, arg, stack_index, env):
    c.visit_exp(arg, stack_index, env)
    # ints should have 2 trailing zeroes
    c.shr(RAX, 6)


def prim_zerop(c, arg, stack_index, env):
    c.visit_exp(arg, stack_index, env)
    c.cmp(RAX, 0)
    c.mov(RAX, 0)
    c.sete("al")
    c.shl(RAX, BOOL_SHIFT)
    c.or_(RAX, BOOL_TAG)


def prim_nullp(c, arg, stack_index, env):
    c.visit_exp(arg, stack_index, env)
    c.emit(f"cmp rax, {NIL_TAG}")
    c.mov(RAX, 0)
    c.emit(f"sete al")
    c.emit(f"shl rax, {BOOL_SHIFT}")
    c.emit(f"or rax, {BOOL_TAG}")


def prim_not(c, arg, stack_index, env):
    c.visit_exp(arg, stack_index, env)
    c.emit(f"xor rax, {BOOL_TAG}")
    c.mov(RAX, 0)
    c.emit(f"sete al")
    c.emit(f"shl rax, {BOOL_SHIFT}")
    c.emit(f"or rax, {BOOL_TAG}")


def prim_integerp(c, arg, stack_index, env):
    c.visit_exp(arg, stack_index, env)
    c.emit(f"and rax, {FIXNUM_MASK}")
    c.emit(f"cmp rax, 0")
    c.mov(RAX, 0)
    c.emit(f"sete al")
    c.emit(f"shl rax, {BOOL_SHIFT}")
    c.emit(f"or rax, {BOOL_TAG}")


def prim_booleanp(c, arg, stack_index, env):
    c.visit_exp(arg, stack_index, env)
    c.emit(f"and rax, {BOOL_MASK}")
    c.emit(f"cmp rax, {BOOL_TAG}")
    c.mov(RAX, 0)
    c.emit(f"sete al")
    c.emit(f"shl rax, {BOOL_SHIFT}")
    c.emit(f"or rax, {BOOL_TAG}")


def offset(reg, si=0):
    if si == 0:
        return f"[{reg}]"
    if si > 0:
        return f"[{reg}+{si}]"
    return f"[{reg}{si}]"


assert offset(RAX, 0) == "[rax]"
assert offset("rsp", -4) == "[rsp-4]"
assert offset("rdi", 8) == "[rdi+8]"


def stack(si):
    return offset("rsp", si)


assert stack(0) == "[rsp]"
assert stack(-2) == "[rsp-2]"
assert stack(4) == "[rsp+4]"


def prim_binplus(c, left, right, stack_index, env):
    c.visit_exp(right, stack_index, env)
    c.emit_stack_store(RAX, stack_index)
    c.visit_exp(left, stack_index - WORD_SIZE, env)
    c.add(RAX, stack(stack_index))


def prim_binminus(c, left, right, stack_index, env):
    c.visit_exp(right, stack_index, env)
    c.emit_stack_store(RAX, stack_index)
    c.visit_exp(left, stack_index - WORD_SIZE, env)
    c.sub(RAX, stack(stack_index))


def prim_binmul(c, left, right, stack_index, env):
    c.visit_exp(right, stack_index, env)
    c.emit_stack_store(RAX, stack_index)
    c.visit_exp(left, stack_index - WORD_SIZE, env)
    # can't just multiply encoded ints due to tag
    c.shr_qword(RAX, FIXNUM_SHIFT)
    c.mul_qword(stack(stack_index))  # multiply by RAX


def prim_cons(c, car, cdr, stack_index, env):
    c.visit_exp(car, stack_index, env)
    c.mov(offset(HEAP_PTR), RAX)
    c.visit_exp(cdr, stack_index, env)
    c.mov(offset(HEAP_PTR, WORD_SIZE), RAX)
    c.mov(RAX, HEAP_PTR)
    c.or_(RAX, PAIR_TAG)
    c.add(HEAP_PTR, PAIR_SIZE)


def prim_car(c, expr, stack_index, env):
    c.visit_exp(expr, stack_index, env)
    c.mov(RAX, offset(RAX, -PAIR_TAG))


def prim_cdr(c, expr, stack_index, env):
    c.visit_exp(expr, stack_index, env)
    c.mov(RAX, offset(RAX, WORD_SIZE-PAIR_TAG))


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

    def mov(self, *args):
        args = ', '.join(str(arg) for arg in args)
        self.emit(f"mov qword {args}")

    def __getattr__(self, name):
        name = name.replace("_", " ").strip()
        def fn(*args):
            if args:
                args = ', '.join(str(arg) for arg in args)
                self.emit(f"{name} {args}")
            else:
                self.emit(name)
        return fn

    def emit_stack_store(self, src_reg, off):
        self.mov(stack(off), src_reg)

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
        self.emit_stack_store(RAX, stack_index)
        new_env[name.value()] = stack_index
        self.visit_let(bindings[1:], body, stack_index - WORD_SIZE, new_env)

    def visit_if(self, cond, consequent, alternative, stack_index, env):
        L0 = self._unique_label()
        L1 = self._unique_label()
        self.visit_exp(cond, stack_index, env)
        self.cmp(RAX, imm(False))
        self.je(L0)
        self.visit_exp(consequent, stack_index, env)
        self.jmp(L1)
        self.emit_label(L0)
        self.visit_exp(alternative, stack_index, env)
        self.emit_label(L1)

    def visit_code(self, formals, body, stack_index, env):
        new_env = env.copy()
        body_si = -WORD_SIZE # return address stored on stack by call
        for idx, formal in enumerate(formals):
            new_env[formal.value()] = body_si
            body_si -= WORD_SIZE
        self.visit_exp(body, body_si, new_env)
        self.ret()

    def visit_labels(self, labels, body, stack_index, env):
        new_env = env.copy()
        body_label = self._unique_label()
        self.jmp(body_label)
        for given_label, lexp in labels:
            label = self._unique_label()
            new_env[given_label.value()] = label
            self.emit_label(label)
            self.visit_exp(lexp, stack_index, new_env)
        self.emit_label(body_label)
        self.visit_exp(body, stack_index, new_env)

    def visit_labelcall(self, lvar, args, stack_index, env):
        for idx, arg in enumerate(args):
            self.visit_exp(arg, stack_index, env)
            self.emit_stack_store(RAX, stack_index)
        self.call(env[lvar.value()])

    def visit_exp(self, x, stack_index, env):
        if is_immediate(x):
            self.mov(RAX, imm(x))
            return
        if is_primcall(x):
            self.visit_primcall(x, stack_index, env)
            return
        if isinstance(x, sexpdata.Symbol):
            idx = env[x.value()]
            if isinstance(idx, str):
                self.mov(RAX, idx)
            else:
                self.mov(RAX, stack(idx))
            return
        if is_let(x):
            bindings = x[1]
            body = x[2]
            self.visit_let(*x[1:], stack_index, env)
            return
        if is_if(x):
            self.visit_if(*x[1:], stack_index, env)
            return
        if is_labels(x):
            self.visit_labels(*x[1:], stack_index, env)
            return
        if is_code(x):
            self.visit_code(*x[1:], stack_index, env)
            return
        if is_labelcall(x):
            self.visit_labelcall(x[1], x[2:], stack_index, env)
            return
        # TODO(emacs): Compile strings (0b011)
        # TODO(emacs): Compile vectors (0b010)
        # TODO(emacs): Compile symbols (0b101)
        # TODO(emacs): Compile closures (0b110)
        raise ValueError(x)

    def compile_program(self, x, env=None):
        self.section(".text")
        self.global_("scheme_entry")
        self.emit_label("scheme_entry")
        self.emit("; The entrypoint scheme_entry is called with a parameter:"
                  "a pointer to the\n; heap. This parameter is passed in rdi.\n"
                  f"; {HEAP_PTR} is not used as a parameter register in calling "
                  "convention\n; since it is reserved for a pointer to the heap")
        self.mov(HEAP_PTR, "rdi")
        if env is None:
            env = {}
        self.visit_exp(x, -WORD_SIZE, env)
        self.ret()


if __name__ == "__main__":
    with open(sys.argv[1], "r") as infile:
        sexp = sexpdata.load(infile, true="#t", false="#f")

    with open(sys.argv[2], "w") as outfile:
        c = Compiler(outfile)
        c.compile_program(sexp)
