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
            return str(immediate_rep(expr))
        case str(_):
            return env[expr]
        case []:
            return str(EMPTY_LIST)
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
        case ["zero?", e]:
            o = compile_expr(e, code, env)
            return bind(f"({o} == {immediate_rep(0)}) ? {immediate_rep(True)} : {immediate_rep(False)}", "zero?")
        case ["not", e]:
            o = compile_expr(e, code, env)
            return bind(f"{o} ^ {BOOL_BIT}", "not")
        case ["integer?", e]:
            o = compile_expr(e, code, env)
            return bind(f"({o} & {FIXNUM_MASK}) ? {immediate_rep(False)} : {immediate_rep(True)}", "integer?")
        case ["boolean?", e]:
            o = compile_expr(e, code, env)
            return bind(f"(({o} & {BOOL_MASK}) == {BOOL_TAG}) ? {immediate_rep(True)} : {immediate_rep(False)}", "boolean?")
        case ["+", e0, e1]:
            l = compile_expr(e0, code, env)
            r = compile_expr(e1, code, env)
            return bind(f"{l} + {r}", "+")
        case ["let", bindings, body]:
            new_env = env.copy()
            for (name, val) in bindings:
                new_env[name] = compile_expr(val, code, env)
            return compile_expr(body, code, new_env)
        case ["if", test, conseq, altern]:
            vtest = compile_expr(test, code, env)
            result = unique_var()
            emit(f"Object {result};")
            emit(f"if ({vtest} != {immediate_rep(False)}) {{")
            emit(f"{result} = {compile_expr(conseq, code, env)};")
            emit("} else {")
            emit(f"{result} = {compile_expr(altern, code, env)};")
            emit("}")
            return result
        case ["cons", car, cdr]:
            vcar = compile_expr(car, code, env)
            vcdr = compile_expr(cdr, code, env)
            return bind(f"cons({vcar}, {vcdr})")
        case ["car", e]:
            o = compile_expr(e, code, env)
            return f"car({o})"
        case ["cdr", e]:
            o = compile_expr(e, code, env)
            return f"cdr({o})"
        case ["funcall", func, *args]:
            clo = compile_expr(func, code, env)
            n = len(args)
            arg_types = "".join([", Object"]*n)
            emit(f"typedef Object (*Func{n})(Object*{arg_types});")
            clo_func = bindprim(f"Func{n}", f"closure_func({clo})")
            clo_env = bindprim("Object *", f"closure_env({clo})")
            vargs = [compile_expr(arg, code, env) for arg in args]
            arg_values = ", ".join([clo_env] + vargs)
            return bind(f"(*{clo_func})({arg_values})")
        case ["closure", str(lvar), *args]:
            n = len(args)
            closure = bind(f"make_closure(FUNC_{lvar}, {n})")
            if args:
                clo_env = bindprim("Object *", f"closure_env({closure})")
            for idx, arg in enumerate(args):
                varg = compile_expr(arg, code, env)
                emit(f"{clo_env}[{idx}] = {varg};")
            return closure
        case _:
            raise NotImplementedError(expr)

def compile_lexpr(lvar, lexpr, code):
    match lexpr:
        case ["code", params, freevars, body]:
            env = {}
            for idx, param in enumerate(params):
                env[param] = param
            for idx, fvar in enumerate(freevars):
                env[fvar] = f"$clo[{idx}]"
            params = ", ".join(["Object *$clo"] + [f"Object {param}" for param in params])
            code.append(f"Object FUNC_{lvar}({params}) {{")
            result = compile_expr(body, code, env)
            code.append(f"return {result};")
            code.append("}")
        case _:
            raise NotImplementedError(lexpr)

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
                compile_lexpr(lvar, lexpr, code)
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

    def test_if(self):
        self.assertEqual(self._run(["if", True, 3, 4]), "3")
        self.assertEqual(self._run(["if", False, 3, 4]), "4")

    def test_cons(self):
        self.assertEqual(self._run(["cons", 3, 4]), "(3 . 4)")
        self.assertEqual(self._run(["cons", ["cons", 1, 2], ["cons", 3, 4]]), "((1 . 2) . (3 . 4))")

    def test_car(self):
        self.assertEqual(self._run(["car", ["cons", 3, 4]]), "3")

    def test_cdr(self):
        self.assertEqual(self._run(["cdr", ["cons", 3, 4]]), "4")

    def test_empty_closure(self):
        self.assertEqual(self._run_program(
            ["labels",
                [
                    ["const", ["code", [], [], 3]],
                ],
                ["closure", "const"],
            ]), "<closure>")

    def test_closure_one_var(self):
        self.assertEqual(self._run_program(
            ["labels",
                [
                    ["const", ["code", [], [], 3]],
                ],
                ["let", [["a", 1]],
                    ["closure", "const", "a"],
                ]
            ]), "<closure>")

    def test_closure_multiple_vars(self):
        self.assertEqual(self._run_program(
            ["labels",
                [
                    ["const", ["code", [], [], 3]],
                ],
                ["let", [["a", 1]],
                    ["closure", "const", "a", "a", "a"],
                ]
            ]), "<closure>")

    def test_funcall_empty_closure(self):
        self.assertEqual(self._run_program(
            ["labels",
                [
                    ["const", ["code", [], [], 3]],
                ],
             ["let", [["f", ["closure", "const"]]],
              ["funcall", "f"]]
            ]), "3")

    def test_funcall_empty_closure_with_params(self):
        self.assertEqual(self._run_program(
            ["labels",
                [
                    ["const", ["code", ["x", "y"], [], ["+", "x", "y"]]],
                ],
             ["let", [["f", ["closure", "const"]]],
              ["funcall", "f", 3, 4]]
            ]), "7")

    def test_funcall_closure_with_freevar(self):
        self.assertEqual(self._run_program(
            ["labels",
                [
                    ["const", ["code", [], ["z"], "z"]],
                ],
             ["let", [["v", 3]],
              ["let", [["f", ["closure", "const", "v"]]],
               ["funcall", "f"]]]
            ]), "3")

    def test_lambda(self):
        self.assertEqual(self._run_program(["lambda", ["x"], "x"]), "<closure>")

    def test_lambda_one_var(self):
        self.assertEqual(self._run_program(
            ["let", [["y", 5]], ["lambda", [], "y"]]),
            "<closure>")

    def test_call_lambda(self):
        self.assertEqual(self._run_program([["lambda", ["x"], "x"], 3]), "3")

    def test_lambda_lift_paper_example(self):
        self.assertEqual(self._run_program(["let", [["x", 5]],
                                            ["lambda", ["y"],
                                             ["lambda", [],
                                              ["+", "x", "y"]]]]),
                         "<closure>")
        self.assertEqual(self._run_program([["let", [["x", 5]],
                                            ["lambda", ["y"],
                                             ["lambda", [],
                                              ["+", "x", "y"]]]], 4]),
                         "<closure>")
        self.assertEqual(self._run_program([[["let", [["x", 5]],
                                            ["lambda", ["y"],
                                             ["lambda", [],
                                              ["+", "x", "y"]]]], 4]]),
                         "9")

if __name__ == "__main__":
    unittest.main()
