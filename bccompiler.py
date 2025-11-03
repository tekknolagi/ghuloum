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
HEAP_MASK = HEAP_ALIGNMENT - 1

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

def is_cons(v):
    return (v & HEAP_MASK) == CONS_TAG

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
    PRIM_ADD, \
    LOAD_LOCAL, \
    STORE_LOCAL, \
    JUMP_IF_FALSE, \
    JUMP, \
    CONS, \
    PRIM_CAR, \
    PRIM_CDR, \
    *_ = range(1000)

class Compiler:
    def __init__(self):
        self.code = []
        self.max_locals_count = 0

    def compile(self, expr, env):
        emit = self.code.append
        def current_pos():
            return len(self.code)
        def placeholder():
            result = current_pos()
            emit(None)
            return result
        def patch_placeholder(pos):
            self.code[pos] = current_pos()
        match expr:
            case bool(_):
                emit(I.LOAD64)
                emit(box_bool(expr))
            case int(_):
                emit(I.LOAD64)
                emit(box_fixnum(expr))
            case str(_):
                match env.get(expr):
                    case ["local", slot]:
                        emit(I.LOAD_LOCAL)
                        emit(slot)
                    case None:
                        raise NameError(f"Unbound variable: {expr}")
                    case v:
                        raise NotImplementedError("name resolution", v)
            case Char():
                emit(I.LOAD64)
                emit(box_char(expr))
            case ["add1", e]:
                self.compile(e, env)
                emit(I.PRIM_ADD1)
            case ["integer->char", e]:
                self.compile(e, env)
                emit(I.PRIM_INTEGER_TO_CHAR)
            case ["char->integer", e]:
                self.compile(e, env)
                emit(I.PRIM_CHAR_TO_INTEGER)
            case ["zero?", e]:
                self.compile(e, env)
                emit(I.PRIM_IS_ZERO)
            case ["not", e]:
                self.compile(e, env)
                emit(I.PRIM_NOT)
            case ["integer?", e]:
                self.compile(e, env)
                emit(I.PRIM_IS_INTEGER)
            case ["boolean?", e]:
                self.compile(e, env)
                emit(I.PRIM_IS_BOOLEAN)
            case ["+", e0, e1]:
                self.compile(e0, env)
                self.compile(e1, env)
                emit(I.PRIM_ADD)
            case ["let", [[name, value]], body]:
                # TODO(max): Support multiple bindings
                self.compile(value, env)
                slot = len(env)
                emit(I.STORE_LOCAL)
                emit(slot)
                self.max_locals_count = max(self.max_locals_count, slot + 1)
                self.compile(body, {**env, name: ["local", slot]})
            case ["if", cond, conseq, altern]:
                self.compile(cond, env)
                emit(I.JUMP_IF_FALSE)
                jump_if_false_pos = placeholder()
                self.compile(conseq, env)
                emit(I.JUMP)
                jump_pos = placeholder()
                patch_placeholder(jump_if_false_pos)
                self.compile(altern, env)
                patch_placeholder(jump_pos)
            case ["cons", e0, e1]:
                self.compile(e0, env)
                self.compile(e1, env)
                emit(I.CONS)
            case ["car", e]:
                self.compile(e, env)
                emit(I.PRIM_CAR)
            case ["cdr", e]:
                self.compile(e, env)
                emit(I.PRIM_CDR)
            case _:
                raise NotImplementedError(expr)

def heap_at(heap, addr, size=WORD_SIZE):
    assert addr >= 0
    return int.from_bytes(heap[addr:addr + size], 'little')

def heap_at_put(heap, addr, val, size=WORD_SIZE):
    assert addr >= 0
    heap[addr:addr + size] = val.to_bytes(size, 'little')

def car(heap, obj):
    assert is_cons(obj)
    addr = obj - CONS_TAG
    return heap_at(heap, addr)

def cdr(heap, obj):
    assert is_cons(obj)
    addr = obj - CONS_TAG
    return heap_at(heap, addr + WORD_SIZE)

class Runtime:
    def __init__(self, heap_size=64):
        self.heap = memoryview(bytearray(heap_size))
        self.heap_ptr = 0

    def interpret(self, code, max_locals_count):
        pc = 0
        stack = []
        # Set up locals space in frame
        stack.extend([0] * max_locals_count)
        frame_base = 0
        def push(val):
            stack.append(val)
        def pop():
            return stack.pop()
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
                    v = pop()
                    push(box_fixnum(unbox_fixnum(v) + 1))
                case I.PRIM_INTEGER_TO_CHAR:
                    v = pop()
                    push(box_char(Char(chr(unbox_fixnum(v)))))
                case I.PRIM_CHAR_TO_INTEGER:
                    v = pop()
                    push(box_fixnum(unbox_char(v).byte))
                case I.PRIM_IS_ZERO:
                    v = pop()
                    push(box_bool(v == box_fixnum(0)))
                case I.PRIM_NOT:
                    v = pop()
                    push(box_bool(not unbox_bool(v)))
                case I.PRIM_IS_INTEGER:
                    v = pop()
                    push(box_bool(is_fixnum(v)))
                case I.PRIM_IS_BOOLEAN:
                    v = pop()
                    push(box_bool(is_bool(v)))
                case I.PRIM_ADD:
                    right = pop()
                    left = pop()
                    push(box_fixnum(unbox_fixnum(left) + unbox_fixnum(right)))
                case I.LOAD_LOCAL:
                    slot = readword()
                    push(stack[frame_base + slot])
                case I.STORE_LOCAL:
                    slot = readword()
                    val = pop()
                    stack[frame_base + slot] = val
                case I.JUMP_IF_FALSE:
                    target = readword()
                    cond = pop()
                    if cond == box_bool(False):
                        pc = target
                case I.JUMP:
                    pc = readword()
                case I.CONS:
                    cdr_ = pop()
                    car_ = pop()
                    heap_at_put(self.heap, self.heap_ptr, car_)
                    heap_at_put(self.heap, self.heap_ptr + WORD_SIZE, cdr_)
                    obj = self.heap_ptr | CONS_TAG
                    push(obj)
                    self.heap_ptr += 2 * WORD_SIZE
                case I.PRIM_CAR:
                    v = pop()
                    push(car(self.heap, v))
                case I.PRIM_CDR:
                    v = pop()
                    push(cdr(self.heap, v))
                case _:
                    raise NotImplementedError(instr)
        # TODO(max): Figure out why this fails for let tests
        # assert len(stack) == frame_base + 1
        return pop()

class EndToEndTests(unittest.TestCase):
    def _run(self, expr, runtime=None):
        c = Compiler()
        c.compile(expr, {})
        if runtime is None:
            runtime = Runtime()
        return runtime.interpret(c.code, c.max_locals_count)
    
    def assertTaggedEqual(self, a, b):
        if is_fixnum(a) and is_fixnum(b):
            return self.assertEqual(unbox_fixnum(a), unbox_fixnum(b))
        if is_char(a) and is_char(b):
            return self.assertEqual(unbox_char(a), unbox_char(b))
        if is_bool(a) and is_bool(b):
            return self.assertEqual(unbox_bool(a), unbox_bool(b))
        self.fail(f"Values not equal: {a} vs {b}")

    def assertIsCons(self, v):
        self.assertEqual((v & HEAP_MASK), CONS_TAG, f"Value is not a cons: {hex(v)}")

    def assertAligned(self, ptr):
        self.assertEqual(ptr % HEAP_ALIGNMENT, 0)

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

    def test_is_integer(self):
        self.assertTaggedEqual(self._run(["integer?", 42]), box_bool(True))
        self.assertTaggedEqual(self._run(["integer?", True]), box_bool(False))
        self.assertTaggedEqual(self._run(["integer?", Char('A')]), box_bool(False))
        self.assertTaggedEqual(self._run(["integer?", ["add1", 5]]), box_bool(True))

    def test_is_boolean(self):
        self.assertTaggedEqual(self._run(["boolean?", True]), box_bool(True))
        self.assertTaggedEqual(self._run(["boolean?", False]), box_bool(True))
        self.assertTaggedEqual(self._run(["boolean?", ["zero?", 0]]), box_bool(True))
        self.assertTaggedEqual(self._run(["boolean?", 42]), box_bool(False))

    def test_add(self):
        self.assertTaggedEqual(self._run(["+", 40, 2]), box_fixnum(42))
        self.assertTaggedEqual(self._run(["+", ["add1", 1], ["add1", 2]]), box_fixnum(5))

    def test_let_binds_name(self):
        expr = ["let", [["x", 3]],
                ["+", "x", 4]]
        self.assertTaggedEqual(self._run(expr), box_fixnum(7))

    def test_let_expression(self):
        expr = ["let", [["x", ["add1", 5]]],
                "x"]
        self.assertTaggedEqual(self._run(expr), box_fixnum(6))

    def test_nested_let(self):
        expr = ["let", [["x", 10]],
                ["let", [["y", ["add1", "x"]]],
                    ["+", "x", "y"]]]
        self.assertTaggedEqual(self._run(expr), box_fixnum(21))

    def test_if_true(self):
        expr = ["if", ["zero?", 0],
                    42,
                    17]
        self.assertTaggedEqual(self._run(expr), box_fixnum(42))

    def test_if_false(self):
        expr = ["if", ["zero?", 1],
                    42,
                    17]
        self.assertTaggedEqual(self._run(expr), box_fixnum(17))

    def test_nested_if(self):
        expr = ["if", ["zero?", 0],
                    ["if", ["zero?", 1],
                        100,
                        200],
                    300]
        self.assertTaggedEqual(self._run(expr), box_fixnum(200))

    def test_cons(self):
        expr = ["cons", 1, 2]
        runtime = Runtime()
        heap_before = runtime.heap_ptr
        obj = self._run(expr, runtime)
        self.assertAligned(runtime.heap_ptr)
        self.assertIsCons(obj)
        self.assertTaggedEqual(car(runtime.heap, obj), box_fixnum(1))
        self.assertTaggedEqual(cdr(runtime.heap, obj), box_fixnum(2))
        self.assertGreater(runtime.heap_ptr, heap_before)

    def test_nested_cons_left(self):
        expr = ["cons", ["cons", 1, 2], 3]
        runtime = Runtime()
        obj = self._run(expr, runtime)
        self.assertTaggedEqual(cdr(runtime.heap, obj), box_fixnum(3))
        self.assertAligned(runtime.heap_ptr)
        self.assertIsCons(obj)
        left = car(runtime.heap, obj)
        self.assertIsCons(left)
        self.assertTaggedEqual(car(runtime.heap, left), box_fixnum(1))
        self.assertTaggedEqual(cdr(runtime.heap, left), box_fixnum(2))
        self.assertTaggedEqual(cdr(runtime.heap, obj), box_fixnum(3))

    def test_nested_cons_right(self):
        expr = ["cons", 1, ["cons", 2, 3]]
        runtime = Runtime()
        obj = self._run(expr, runtime)
        self.assertAligned(runtime.heap_ptr)
        self.assertIsCons(obj)
        self.assertTaggedEqual(car(runtime.heap, obj), box_fixnum(1))
        right = cdr(runtime.heap, obj)
        self.assertIsCons(right)
        self.assertTaggedEqual(car(runtime.heap, right), box_fixnum(2))
        self.assertTaggedEqual(cdr(runtime.heap, right), box_fixnum(3))

    def test_car(self):
        expr = ["car", ["cons", 10, 20]]
        self.assertTaggedEqual(self._run(expr), box_fixnum(10))

    def test_cdr(self):
        expr = ["cdr", ["cons", 10, 20]]
        self.assertTaggedEqual(self._run(expr), box_fixnum(20))

if __name__ == "__main__":
    unittest.main()
