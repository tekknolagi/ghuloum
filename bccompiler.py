import unittest

WORD_SIZE = 8
FIXNUM_SHIFT = 2
FIXNUM_MASK = 0b11
FIXNUM_TAG = 0b00
CHAR_TAG = 0b00001111
CHAR_SHIFT = 8
BOOL_TAG = 0b0011111
BOOL_SHIFT = 7
BOOL_MASK = 0b1111111
BOOL_BIT = 1 << BOOL_SHIFT
EMPTY_LIST = 0b00101111
CONS_TAG = 0b001
CLOSURE_TAG = 0b110
HEAP_ALIGNMENT = 2 * WORD_SIZE

def box_fixnum(n):
    # TODO(max): Check range
    return (n << FIXNUM_SHIFT) | FIXNUM_TAG

def unbox_fixnum(v):
    assert (v & FIXNUM_MASK) == FIXNUM_TAG
    return v >> FIXNUM_SHIFT

def box_char(c):
    return (c.byte << CHAR_SHIFT) | CHAR_TAG

def unbox_char(v):
    assert (v & 0xFF) == CHAR_TAG
    byte = (v >> CHAR_SHIFT) & 0xFF
    return Char(chr(byte))

def immediate_rep(val):
    match val:
        case bool(_):
            return (val << BOOL_SHIFT) | BOOL_TAG
        case int(_):
            return box_fixnum(val)
        case Char():
            return box_char(val)
        case _:
            raise NotImplementedError(val)

class Char:
    def __init__(self, c):
        b = c.encode("utf-8")
        assert len(b) == 1
        self.byte = b[0]

    def __eq__(self, other):
        return isinstance(other, Char) and self.byte == other.byte

    def __repr__(self):
        return f"Char({self.byte})"

BUILTINS = frozenset({
    "add1", "integer->char",
    "char->integer", "null?", "zero?",
    "not", "integer?", "boolean?", "+",
    "cons", "car", "cdr",
})

class I:
    LOAD64, \
    PRIM_ADD1, \
    PRIM_INTEGER_TO_CHAR, \
    PRIM_CHAR_TO_INTEGER, \
    *_ = range(1000)

def compile_expr(expr, code, si, env):
    emit = code.append
    match expr:
        case int(_) | Char():
            emit(I.LOAD64)
            emit(immediate_rep(expr))
        case ["add1", e]:
            compile_expr(e, code, si, env)
            emit(I.PRIM_ADD1)
        case ["integer->char", e]:
            compile_expr(e, code, si, env)
            emit(I.PRIM_INTEGER_TO_CHAR)
        case ["char->integer", e]:
            compile_expr(e, code, si, env)
            emit(I.PRIM_CHAR_TO_INTEGER)
        case _:
            raise NotImplementedError(expr)

def interpret(code):
    pc = 0
    stack = []
    heap = bytearray()
    def push(val):
        stack.append(val)
    def readword():
        nonlocal pc
        val = code[pc]
        pc += 1
        return val
    while pc < len(code):
        instr = readword()
        match instr:
            case I.LOAD64:
                push(readword())
            case I.PRIM_ADD1:
                v = stack.pop()
                push(box_fixnum(unbox_fixnum(v) + 1))
            case I.PRIM_INTEGER_TO_CHAR:
                v = stack.pop()
                push(immediate_rep(Char(chr(unbox_fixnum(v)))))
            case I.PRIM_CHAR_TO_INTEGER:
                v = stack.pop()
                push(box_fixnum(unbox_char(v).byte))
            case _:
                raise NotImplementedError(instr)
    return stack.pop()

class EndToEndTests(unittest.TestCase):
    def _run(self, expr):
        bytecode = []
        compile_expr(expr, bytecode, 0, {})
        return interpret(bytecode)

    # TODO(max): Add assertEqual that understands tagged values

    def test_positive_fixnum(self):
        self.assertEqual(self._run(42), immediate_rep(42))

    def test_negative_fixnum(self):
        self.assertEqual(self._run(-17), immediate_rep(-17))

    def test_character(self):
        self.assertEqual(self._run(Char('A')), immediate_rep(Char('A')))

    def test_add1(self):
        self.assertEqual(self._run(["add1", 41]), immediate_rep(42))

    def test_nested_add1(self):
        self.assertEqual(self._run(["add1", ["add1", 3]]), immediate_rep(5))

    def test_integer_to_char(self):
        self.assertEqual(self._run(["integer->char", 65]), immediate_rep(Char('A')))

    def test_nested_integer_to_char(self):
        self.assertEqual(self._run(["integer->char", ["add1", 65]]), immediate_rep(Char('B')))

    def test_char_to_integer(self):
        self.assertEqual(self._run(["char->integer", Char('A')]), immediate_rep(65))

    def test_nested_char_to_integer(self):
        self.assertEqual(self._run(["char->integer", ["integer->char", 66]]), immediate_rep(66))

if __name__ == "__main__":
    unittest.main()
