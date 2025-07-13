import tempfile
import unittest
from run import run

FIXNUM_SHIFT = 2

def box_fixnum(val):
    assert isinstance(val, int)
    return val << FIXNUM_SHIFT

def compile_expr(expr, code):
    match expr:
        case int(_):
            code.append(f"mov rax, {box_fixnum(expr)}")
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
        run(["clang", "-Os", "-masm=intel", f.name, "runtime.c", "-o", outfile], verbose=verbose)
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

if __name__ == "__main__":
    unittest.main()
