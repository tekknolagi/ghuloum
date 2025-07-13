import tempfile
import unittest
from run import run

WORD_SIZE=8
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

def immediate_rep(val):
    assert isinstance(val, int)

def immediate_rep(val):
    match val:
        case bool(_):
            return (val << BOOL_SHIFT) | BOOL_TAG
        case int(_):
            return val << FIXNUM_SHIFT
        case Char():
            return (val.byte << CHAR_SHIFT) | CHAR_TAG
        case _:
            raise NotImplementedError(val)

class Char:
    def __init__(self, c):
        b = c.encode("utf-8")
        assert len(b) == 1
        self.byte = b[0]

def compile_expr(expr, code, si, env):
    emit = code.append
    def stack_at(si):
        assert si < 0
        return f"[rsp{si}]"
    match expr:
        case int(_) | Char():
            emit(f"mov rax, {immediate_rep(expr)}")
        case str(_):
            var_si = env[expr]
            emit(f"mov rax, {stack_at(var_si)}")
        case []:
            emit(f"mov rax, {EMPTY_LIST}")
        case ["add1", e]:
            compile_expr(e, code, si, env)
            emit(f"add rax, {immediate_rep(1)}")
        case ["integer->char", e]:
            compile_expr(e, code, si, env)
            emit(f"shl rax, {CHAR_SHIFT-FIXNUM_SHIFT}")
            emit(f"or rax, {CHAR_TAG}")
        case ["char->integer", e]:
            compile_expr(e, code, si, env)
            emit(f"shr rax, {CHAR_SHIFT-FIXNUM_SHIFT}")
        case ["null?", e]:
            compile_expr(e, code, si, env)
            emit(f"cmp rax, {EMPTY_LIST}")
            emit(f"mov rax, 0")
            emit(f"sete al")
            emit(f"shl rax, {BOOL_SHIFT}")
            emit(f"or rax, {BOOL_TAG}")
        case ["zero?", e]:
            compile_expr(e, code, si, env)
            emit(f"test rax, rax")
            emit(f"mov rax, 0")
            emit(f"sete al")
            emit(f"shl rax, {BOOL_SHIFT}")
            emit(f"or rax, {BOOL_TAG}")
        case ["not", e]:
            compile_expr(e, code, si, env)
            emit(f"xor rax, {BOOL_BIT}")
        case ["integer?", e]:
            compile_expr(e, code, si, env)
            emit(f"and al, {FIXNUM_MASK}")
            emit(f"test al, al")
            emit(f"mov rax, 0")
            emit(f"sete al")
            emit(f"shl rax, {BOOL_SHIFT}")
            emit(f"or rax, {BOOL_TAG}")
        case ["boolean?", e]:
            compile_expr(e, code, si, env)
            emit(f"and al, {BOOL_MASK}")
            emit(f"cmp al, {BOOL_TAG}")
            emit(f"mov rax, 0")
            emit(f"sete al")
            emit(f"shl rax, {BOOL_SHIFT}")
            emit(f"or rax, {BOOL_TAG}")
        case ["+", e0, e1]:
            compile_expr(e0, code, si, env)
            emit(f"mov {stack_at(si)}, rax")
            compile_expr(e1, code, si-WORD_SIZE, env)
            emit(f"add rax, {stack_at(si)}")
        case ["let", bindings, body]:
            new_env = env.copy()
            new_si = si
            while bindings:
                (name, val) = bindings.pop(0)
                compile_expr(val, code, new_si, env)
                emit(f"mov {stack_at(new_si)}, rax")
                new_env[name] = new_si
                new_si -= WORD_SIZE
            compile_expr(body, code, new_si, new_env)
        case _:
            raise NotImplementedError(expr)

def compile_program(expr):
    code = [".intel_syntax", ".global scheme_entry", "scheme_entry:"]
    compile_expr(expr, code, si=-WORD_SIZE, env={})
    code.append("ret")
    return "\n".join(code)

def link(program, outfile=None, verbose=True):
    if not outfile:
        outfile = "a.out"
    with tempfile.NamedTemporaryFile(suffix=".s") as f:
        f.write(program.encode("utf-8"))
        f.flush()
        run(["ccache", "clang", "-O0", "-ggdb", "-c", "runtime.c"], verbose=verbose)
        compiled_object = f"{f.name}.o"
        run(["ccache", "clang", "-O0", "-masm=intel", f.name, "-c", "-o", compiled_object], verbose=verbose)
        run(["ccache", "clang", "-O0", "-masm=intel", compiled_object, "runtime.o", "-o", outfile], verbose=verbose)
    return outfile

class EndToEndTests(unittest.TestCase):
    def _run(self, program):
        asm = compile_program(program)
        with tempfile.NamedTemporaryFile(suffix=".out", delete_on_close=False) as f:
            link(asm, f.name, verbose=False)
            f.close()
            result = run([f.name], verbose=False, capture_output=True)
        self.assertIsNot(result.stdout, None)
        return result.stdout.removesuffix("\n")

    def test_int(self):
        self.assertEqual(self._run(123), "123")

    def test_char(self):
        self.assertEqual(self._run(Char("a")), "'a'")

    def test_bool(self):
        self.assertEqual(self._run(True), "#t")
        self.assertEqual(self._run(False), "#f")

    def test_empty_list(self):
        self.assertEqual(self._run([]), "()")

    def test_add1(self):
        self.assertEqual(self._run(["add1", 3]), "4")
        self.assertEqual(self._run(["add1", ["add1", 3]]), "5")

    def test_integer_to_char(self):
        self.assertEqual(self._run(["integer->char", 97]), "'a'")

    def test_char_to_integer(self):
        self.assertEqual(self._run(["char->integer", Char("a")]), "97")

    def test_nullp(self):
        self.assertEqual(self._run(["null?", 123]), "#f")
        self.assertEqual(self._run(["null?", []]), "#t")

    def test_zerop(self):
        self.assertEqual(self._run(["zero?", 123]), "#f")
        self.assertEqual(self._run(["zero?", 0]), "#t")
        self.assertEqual(self._run(["zero?", []]), "#f")

    def test_not(self):
        self.assertEqual(self._run(["not", True]), "#f")
        self.assertEqual(self._run(["not", False]), "#t")

    def test_integerp(self):
        self.assertEqual(self._run(["integer?", 123]), "#t")
        self.assertEqual(self._run(["integer?", 0]), "#t")
        self.assertEqual(self._run(["integer?", []]), "#f")
        self.assertEqual(self._run(["integer?", Char("a")]), "#f")
        self.assertEqual(self._run(["integer?", True]), "#f")
        self.assertEqual(self._run(["integer?", False]), "#f")

    def test_booleanp(self):
        self.assertEqual(self._run(["boolean?", 123]), "#f")
        self.assertEqual(self._run(["boolean?", 0]), "#f")
        self.assertEqual(self._run(["boolean?", []]), "#f")
        self.assertEqual(self._run(["boolean?", Char("a")]), "#f")
        self.assertEqual(self._run(["boolean?", True]), "#t")
        self.assertEqual(self._run(["boolean?", False]), "#t")

    def test_add(self):
        self.assertEqual(self._run(["+", 3, 4]), "7")
        self.assertEqual(self._run(["+", ["+", 1, 2], ["+", 3, 4]]), "10")

    def test_let_no_bindings(self):
        self.assertEqual(self._run(["let", [], 3]), "3")

    def test_let_one_binding(self):
        self.assertEqual(self._run(["let", [["a", 3]], "a"]), "3")

    def test_let_multiple_bindings(self):
        self.assertEqual(self._run(["let", [["a", 3], ["b", 4]], ["+", "a", "b"]]), "7")

if __name__ == "__main__":
    unittest.main()
