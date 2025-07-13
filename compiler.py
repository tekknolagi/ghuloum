import tempfile
import unittest
from run import run

FIXNUM_SHIFT = 2
CHAR_TAG = 0b00001111
CHAR_SHIFT = 8
BOOL_TAG = 0b0011111
BOOL_SHIFT = 7
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

def compile_expr(expr, code):
    match expr:
        case int(_) | Char():
            code.append(f"mov rax, {immediate_rep(expr)}")
        case []:
            code.append(f"mov rax, {EMPTY_LIST}")
        case ["add1", e]:
            compile_expr(e, code)
            code.append(f"add rax, {immediate_rep(1)}")
        case ["integer->char", e]:
            compile_expr(e, code)
            code.append(f"shl rax, {CHAR_SHIFT-FIXNUM_SHIFT}")
            code.append(f"or rax, {CHAR_TAG}")
        case ["char->integer", e]:
            compile_expr(e, code)
            code.append(f"shr rax, {CHAR_SHIFT-FIXNUM_SHIFT}")
        case _:
            raise NotImplementedError(expr)

def compile_program(expr):
    code = [".intel_syntax", ".global scheme_entry", "scheme_entry:"]
    compile_expr(expr, code)
    code.append("ret")
    return "\n".join(code)

def link(program, outfile=None, verbose=True):
    if not outfile:
        outfile = "a.out"
    with tempfile.NamedTemporaryFile(suffix=".s") as f:
        f.write(program.encode("utf-8"))
        f.flush()
        run(["clang", "-O0", "-masm=intel", f.name, "runtime.c", "-o", outfile], verbose=verbose)
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

if __name__ == "__main__":
    unittest.main()
