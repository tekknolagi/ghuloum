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

def is_fixnum(v):
    return (v & FIXNUM_MASK) == FIXNUM_TAG

def box_fixnum(n):
    assert isinstance(n, int)
    # TODO(max): Check range
    return (n << FIXNUM_SHIFT) | FIXNUM_TAG

def unbox_fixnum(v):
    assert (v & FIXNUM_MASK) == FIXNUM_TAG
    return v >> FIXNUM_SHIFT

def is_char(v):
    return (v & 0xFF) == CHAR_TAG

def box_char(c):
    assert isinstance(c, Char)
    return (c.byte << CHAR_SHIFT) | CHAR_TAG

def unbox_char(v):
    assert (v & 0xFF) == CHAR_TAG
    byte = (v >> CHAR_SHIFT) & 0xFF
    return Char(chr(byte))

def is_bool(v):
    return (v & BOOL_MASK) == BOOL_TAG

def box_bool(b):
    assert isinstance(b, bool)
    return (b << BOOL_SHIFT) | BOOL_TAG

def unbox_bool(v):
    assert (v & BOOL_MASK) == BOOL_TAG
    return bool((v >> BOOL_SHIFT) & 0x1)

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
    PRIM_IS_NULL, \
    PRIM_IS_ZERO, \
    PRIM_NOT, \
    PRIM_IS_INTEGER, \
    PRIM_IS_BOOLEAN, \
    *_ = range(1000)

def compile_expr(expr, code, si, env):
    emit = code.append
    match expr:
        case bool(_):
            emit(I.LOAD64)
            emit(box_bool(expr))
        case int(_):
            emit(I.LOAD64)
            emit(box_fixnum(expr))
        case Char():
            emit(I.LOAD64)
            emit(box_char(expr))
        case ["add1", e]:
            compile_expr(e, code, si, env)
            emit(I.PRIM_ADD1)
        case ["integer->char", e]:
            compile_expr(e, code, si, env)
            emit(I.PRIM_INTEGER_TO_CHAR)
        case ["char->integer", e]:
            compile_expr(e, code, si, env)
            emit(I.PRIM_CHAR_TO_INTEGER)
        case ["zero?", e]:
            compile_expr(e, code, si, env)
            emit(I.PRIM_IS_ZERO)
        case ["not", e]:
            compile_expr(e, code, si, env)
            emit(I.PRIM_NOT)
        case ["integer?", e]:
            compile_expr(e, code, si, env)
            emit(I.PRIM_IS_INTEGER)
        case ["boolean?", e]:
            compile_expr(e, code, si, env)
            emit(I.PRIM_IS_BOOLEAN)
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
                push(box_char(Char(chr(unbox_fixnum(v)))))
            case I.PRIM_CHAR_TO_INTEGER:
                v = stack.pop()
                push(box_fixnum(unbox_char(v).byte))
            case I.PRIM_IS_ZERO:
                v = stack.pop()
                push(box_bool(v == box_fixnum(0)))
            case I.PRIM_NOT:
                v = stack.pop()
                push(box_bool(not unbox_bool(v)))
            case _:
                raise NotImplementedError(instr)
    return stack.pop()

class EndToEndTests(unittest.TestCase):
    def _run(self, expr):
        bytecode = []
        compile_expr(expr, bytecode, 0, {})
        return interpret(bytecode)

    # TODO(max): Add assertEqual that understands tagged values
    
    def assertTaggedEqual(self, a, b):
        if is_fixnum(a) and is_fixnum(b):
            return self.assertEqual(unbox_fixnum(a), unbox_fixnum(b))
        if is_char(a) and is_char(b):
            return self.assertEqual(unbox_char(a), unbox_char(b))
        if is_bool(a) and is_bool(b):
            return self.assertEqual(unbox_bool(a), unbox_bool(b))
        self.fail(f"Values not equal: {a} vs {b}")

    def test_positive_fixnum(self):
        self.assertTaggedEqual(self._run(42), box_fixnum(42))

    def test_negative_fixnum(self):
        self.assertTaggedEqual(self._run(-17), box_fixnum(-17))

    def test_boolean_true(self):
        self.assertTaggedEqual(self._run(True), box_bool(True))

    def test_boolean_false(self):
        self.assertTaggedEqual(self._run(False), box_bool(False))

    def test_character(self):
        self.assertTaggedEqual(self._run(Char('A')), box_char(Char('A')))

    def test_add1(self):
        self.assertTaggedEqual(self._run(["add1", 41]), box_fixnum(42))

    def test_nested_add1(self):
        self.assertTaggedEqual(self._run(["add1", ["add1", 3]]), box_fixnum(5))

    def test_integer_to_char(self):
        self.assertTaggedEqual(self._run(["integer->char", 65]), box_char(Char('A')))

    def test_nested_integer_to_char(self):
        self.assertTaggedEqual(self._run(["integer->char", ["add1", 65]]), box_char(Char('B')))

    def test_char_to_integer(self):
        self.assertTaggedEqual(self._run(["char->integer", Char('A')]), box_fixnum(65))

    def test_nested_char_to_integer(self):
        self.assertTaggedEqual(self._run(["char->integer", ["integer->char", 66]]), box_fixnum(66))

    def test_is_zero(self):
        self.assertTaggedEqual(self._run(["zero?", ["add1", -1]]), box_bool(True))
        self.assertTaggedEqual(self._run(["zero?", ["add1", 0]]), box_bool(False))

    def test_not(self):
        self.assertTaggedEqual(self._run(["not", ["zero?", 0]]), box_bool(False))
        self.assertTaggedEqual(self._run(["not", ["zero?", 1]]), box_bool(True))

if __name__ == "__main__":
    unittest.main()
