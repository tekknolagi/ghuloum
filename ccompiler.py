# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "unittest-parallel",
# ]
# ///
import tempfile
import unittest
from run import run

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

NEXT_LABEL = -1
NEXT_VARIABLE = -1

def compile_expr(expr, code, env):
    emit = code.append
    def comment(msg):
        emit(f"// {msg}")
    def unique_label():
        global NEXT_LABEL
        NEXT_LABEL += 1
        return f"L{NEXT_LABEL}"
    def unique_var():
        global NEXT_VARIABLE
        NEXT_VARIABLE += 1
        return f"v{NEXT_VARIABLE}"
    def bindprim(t, e, comment_=""):
        if comment_:
            comment(comment_)
        v = unique_var()
        emit(f"{t} {v} = {e};")
        return v
    def bind(e, comment_=""):
        return bindprim("Object", e, comment_)
    match expr:
        case int(_) | Char():
            return immediate_rep(expr)
        case []:
            return EMPTY_LIST
        case ["add1", e]:
            o = compile_expr(e, code, env)
            return bind(f"{o} + {immediate_rep(1)}", "add1")
        case ["integer->char", e]:
            o = compile_expr(e, code, env)
            return bind(f"({o} << {CHAR_SHIFT - FIXNUM_SHIFT}) | {CHAR_TAG}", "integer->char")
        case ["char->integer", e]:
            o = compile_expr(e, code, env)
            return bind(f"{o} >> {CHAR_SHIFT - FIXNUM_SHIFT}", "char->integer")
        case ["null?", e]:
            o = compile_expr(e, code, env)
            return bind(f"({o} == {EMPTY_LIST}) ? {immediate_rep(True)} : {immediate_rep(False)}", "null?")
        case _:
            raise NotImplementedError(expr)

def lift_lambdas_rec(expr, labels, bound, free):
    match expr:
        case int(_) | Char():
            return expr
        case str(_) if expr in bound or expr in BUILTINS:
            return expr
        case str(_):
            free.add(expr)
            return expr
        case ["lambda", params, body]:
            body_free = set()
            assert all(isinstance(v, str) for v in params)
            body = lift_lambdas_rec(body, labels, set(params), body_free)
            assert all(isinstance(v, str) for v in body_free)
            free.update(body_free - bound)
            body_free = sorted(body_free)
            label = f"f{len(labels)}"
            labels[label] = ["code", params, body_free, body]
            return ["closure", label, *body_free]
        case ["let", bindings, body]:
            new_bindings = []
            names = {name for name, _ in bindings}
            for name, val_expr in bindings:
                new_bindings.append([name, lift_lambdas_rec(val_expr, labels, bound, free)])
            new_body = lift_lambdas_rec(body, labels, bound | names, free)
            return ["let", new_bindings, new_body]
        case ["if", test, conseq, alt]:
            return ["if",
                    lift_lambdas_rec(test, labels, bound, free),
                    lift_lambdas_rec(conseq, labels, bound, free),
                    lift_lambdas_rec(alt, labels, bound, free)]
        case [func, *args]:
            result = [] if isinstance(func, str) and func in BUILTINS else ["funcall"]
            for e in expr:
                result.append(lift_lambdas_rec(e, labels, bound, free))
            return result
        case _:
            raise NotImplementedError(expr)

def lift_lambdas(expr):
    labels = {}
    expr = lift_lambdas_rec(expr, labels, set(), set())
    labels = [[name, code] for name, code in labels.items()]
    return ["labels", labels, expr]

def compile_program(expr):
    with open("cruntime.c", "r") as f:
        cruntime = f.read()
    code = [
        cruntime
    ]
    match expr:
        case ["labels", labels, body]:
            for (lvar, lexpr) in labels:
                code.append(f"void {lvar}() {{")
                compile_lexpr(lexpr, code)
                code.append("}")
            code.append("Object scheme_entry(Object *closure) {")
            result = compile_expr(body, code, env={})
            code.append(f"return {result};")
            code.append("}")
        case _:
            expr = lift_lambdas(expr)
            assert isinstance(expr, list) and expr[0] == "labels"
            return compile_program(expr)
    return "\n".join(code)

HAVE_CCACHE = True

def link(program, outfile=None, verbose=True):
    if not outfile:
        outfile = "a.out"
    ccache = ["ccache"] if HAVE_CCACHE else []
    with tempfile.NamedTemporaryFile(suffix=".c") as f:
        f.write(program.encode("utf-8"))
        f.flush()
        run([*ccache, "clang", "-O0", f.name, "-o", outfile], verbose=verbose)
    return outfile

class EndToEndTests(unittest.TestCase):
    def _run(self, expr):
        return self._run_program(["labels", [], expr])

    def _run_program(self, program):
        asm = compile_program(program)
        with tempfile.NamedTemporaryFile(suffix=".out", delete_on_close=False) as f:
            link(asm, f.name, verbose=False)
            f.close()
            result = run([f.name], verbose=False, capture_output=True)
        self.assertIsNot(result.stdout, None)
        return result.stdout.removesuffix("\n")

    def test_int(self):
        self.assertEqual(self._run(123), "123")

    def test_negative_int(self):
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

if __name__ == "__main__":
    unittest.main()
