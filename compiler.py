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

NEXT_LABEL = -1

CLOSURE_BASE = "rdi"
HEAP_BASE = "rsi"

def indirect(reg, offset):
    if offset >= 0:
        return f"[{reg}+{offset}]"
    else:
        return f"[{reg}{offset}]"

def stack_at(si):
    assert si < 0
    return indirect("rsp", si)

BUILTINS = frozenset({
    "add1", "integer->char",
    "char->integer", "null?", "zero?",
    "not", "integer?", "boolean?", "+",
    "cons", "car", "cdr",
})

def compile_expr(expr, code, si, env):
    emit = code.append
    def comment(msg):
        emit(f"# {msg}")
    def heap_at(offset):
        return indirect(HEAP_BASE, offset)
    def unique_label():
        global NEXT_LABEL
        NEXT_LABEL += 1
        return f"L{NEXT_LABEL}"
    def align(size):
        if size % HEAP_ALIGNMENT == 0:
            return size
        return size + WORD_SIZE
    match expr:
        case int(_) | Char():
            emit(f"mov rax, {immediate_rep(expr)}")
        case str(_):
            emit(f"mov rax, {env[expr]}")
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
            for (name, val) in bindings:
                comment(f"Code for {name}")
                compile_expr(val, code, new_si, env)
                comment(f"Store {name} on the stack")
                emit(f"mov {stack_at(new_si)}, rax")
                new_env[name] = stack_at(new_si)
                new_si -= WORD_SIZE
            compile_expr(body, code, new_si, new_env)
        case ["if", test, conseq, altern]:
            L0 = unique_label()
            L1 = unique_label()
            compile_expr(test, code, si, env)
            emit(f"cmp rax, {immediate_rep(False)}")
            emit(f"je {L0}")
            compile_expr(conseq, code, si, env)
            emit(f"jmp {L1}")
            emit(f"{L0}:")
            compile_expr(altern, code, si, env)
            emit(f"{L1}:")
        case ["cons", car, cdr]:
            comment("Compile car")
            compile_expr(car, code, si, env)
            emit(f"mov {stack_at(si)}, rax")
            comment("Compile cdr")
            compile_expr(cdr, code, si-WORD_SIZE, env)
            emit(f"mov {heap_at(WORD_SIZE)}, rax")
            emit(f"mov rax, {stack_at(si)}")
            emit(f"mov {heap_at(0)}, rax")
            comment("Tag a cons cell")
            emit(f"lea rax, {heap_at(CONS_TAG)}")
            size = align(2 * WORD_SIZE)
            comment("Bump the heap pointer")
            emit(f"add {HEAP_BASE}, {size}")
        case ["car", cell]:
            compile_expr(cell, code, si, env)
            emit(f"mov rax, {indirect('rax', 0*WORD_SIZE-CONS_TAG)}")
        case ["cdr", cell]:
            compile_expr(cell, code, si, env)
            emit(f"mov rax, {indirect('rax', 1*WORD_SIZE-CONS_TAG)}")
        case ["labelcall", str(label), *args]:
            new_si = si - WORD_SIZE  # Save a word for the return address
            for arg in args:
                compile_expr(arg, code, new_si, env)
                emit(f"mov {stack_at(new_si)}, rax")
                new_si -= WORD_SIZE
            # Align to one word before the return address
            si_adjust = abs(si+WORD_SIZE)
            emit(f"sub rsp, {si_adjust}")
            emit(f"call {label}")
            emit(f"add rsp, {si_adjust}")
        case ["funcall", func, *args]:
            # Save a word for the return address and the closure pointer
            clo_si = si - WORD_SIZE
            retaddr_si = clo_si - WORD_SIZE
            new_si = retaddr_si
            # Evaluate arguments
            for arg in args:
                compile_expr(arg, code, new_si, env)
                emit(f"mov {stack_at(new_si)}, rax")
                new_si -= WORD_SIZE
            compile_expr(func, code, new_si, env)
            # Save the current closure pointer
            emit(f"mov {stack_at(clo_si)}, {CLOSURE_BASE}")
            emit(f"mov {CLOSURE_BASE}, rax")
            # Align to one word before the return address
            si_adjust = abs(si)
            emit(f"sub rsp, {si_adjust}")
            emit(f"call {indirect(CLOSURE_BASE, -CLOSURE_TAG)}")
            emit(f"add rsp, {si_adjust}")
            emit(f"mov {CLOSURE_BASE}, {stack_at(clo_si)}")
        case ["closure", str(lvar), *args]:
            comment("Get a pointer to the label")
            emit(f"lea rax, {lvar}")
            emit(f"mov {heap_at(0)}, rax")
            for idx, arg in enumerate(args):
                assert isinstance(arg, str)
                comment(f"Load closure cell #{idx}")
                # Just a variable lookup; guaranteed not to allocate
                compile_expr(arg, code, si, env)
                emit(f"mov {heap_at((idx+1)*WORD_SIZE)}, rax")
            comment("Tag a closure pointer")
            emit(f"lea rax, {heap_at(CLOSURE_TAG)}")
            comment("Bump the heap pointer")
            size = align(WORD_SIZE + len(args)*WORD_SIZE)
            emit(f"add {HEAP_BASE}, {size}")
        case _:
            raise NotImplementedError(expr)

def compile_lexpr(lexpr, code):
    match lexpr:
        case ["code", params, freevars, body]:
            env = {}
            for idx, param in enumerate(params):
                env[param] = stack_at(-(idx+1)*WORD_SIZE)
            for idx, fvar in enumerate(freevars):
                env[fvar] = indirect(CLOSURE_BASE, (idx+1)*WORD_SIZE - CLOSURE_TAG)
            compile_expr(body, code, si=-(len(env)+1)*WORD_SIZE, env=env)
            code.append("ret")
        case _:
            raise NotImplementedError(lexpr)

class LambdaConverter:
    def __init__(self):
        self.labels = {}

    def push_label(self, params, freevars, body):
        result = f"f{len(self.labels)}"
        self.labels[result] = ["code", params, freevars, body]
        return result

    def convert(self, expr, bound, free):
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
                body = self.convert(body, set(params), body_free)
                assert all(isinstance(v, str) for v in body_free)
                free.update(body_free - bound)
                body_free = sorted(body_free)
                label = self.push_label(params, body_free, body)
                return ["closure", label, *body_free]
            case ["let", bindings, body]:
                new_bindings = []
                names = {name for name, _ in bindings}
                for name, val_expr in bindings:
                    new_bindings.append([name, self.convert(val_expr, bound, free)])
                new_body = self.convert(body, bound | names, free)
                return ["let", new_bindings, new_body]
            case ["if", test, conseq, alt]:
                return ["if",
                        self.convert(test, bound, free),
                        self.convert(conseq, bound, free),
                        self.convert(alt, bound, free)]
            case [func, *args]:
                result = [] if isinstance(func, str) and func in BUILTINS else ["funcall"]
                for e in expr:
                    result.append(self.convert(e, bound, free))
                return result
            case _:
                raise NotImplementedError(expr)

def lift_lambdas(expr):
    conv = LambdaConverter()
    expr = conv.convert(expr, set(), set())
    labels = [[name, code] for name, code in conv.labels.items()]
    return ["labels", labels, expr]

def compile_program(expr):
    code = [".intel_syntax", ".global scheme_entry"]
    match expr:
        case ["labels", labels, body]:
            for (lvar, lexpr) in labels:
                code.append(f"{lvar}:")
                compile_lexpr(lexpr, code)
            code.append("scheme_entry:")
            compile_expr(body, code, si=-WORD_SIZE, env={})
            code.append("ret")
        case _:
            expr = lift_lambdas(expr)
            assert isinstance(expr, list) and expr[0] == "labels"
            return compile_program(expr)
    return "\n".join(code)

class LambdaTests(unittest.TestCase):
    def test_int(self):
        self.assertEqual(lift_lambdas(3), ["labels", [], 3])

    def test_bool(self):
        self.assertEqual(lift_lambdas(True), ["labels", [], True])
        self.assertEqual(lift_lambdas(False), ["labels", [], False])

    def test_char(self):
        self.assertEqual(lift_lambdas(Char("a")), ["labels", [], Char("a")])

    def test_freevar(self):
        self.assertEqual(lift_lambdas("x"), ["labels", [], "x"])

    def test_call_plus(self):
        self.assertEqual(lift_lambdas(["+", 3, 4]), ["labels", [], ["+", 3, 4]])

    def test_call(self):
        self.assertEqual(lift_lambdas(["f", 3, 4]), ["labels", [], ["funcall", "f", 3, 4]])

    def test_lambda_no_params_no_freevars(self):
        self.assertEqual(lift_lambdas(["lambda", [], 3]),
                         ["labels", [
                             ["f0", ["code", [], [], 3]],
                         ], ["closure", "f0"]])

    def test_lambda_no_params_with_freevars(self):
        self.assertEqual(lift_lambdas(["lambda", [], "z"]),
                         ["labels", [
                             ["f0", ["code", [], ["z"], "z"]],
                         ], ["closure", "f0", "z"]])

    def test_lambda_with_params_no_freevars(self):
        self.assertEqual(lift_lambdas(["lambda", ["x"], "x"]),
                         ["labels", [
                             ["f0", ["code", ["x"], [], "x"]],
                         ], ["closure", "f0"]])

    def test_lambda_with_params_and_freevars(self):
        self.assertEqual(lift_lambdas(["lambda", ["x"], ["+", "x", "y"]]),
                         ["labels",
                          [["f0", ["code", ["x"], ["y"], ["+", "x", "y"]]]],
                          ["closure", "f0", "y"]])

    def test_let(self):
        self.assertEqual(lift_lambdas(["let", [["x", 5]], "x"]),
                         ["labels", [], ["let", [["x", 5]], "x"]])

    def test_let_lambda(self):
        self.assertEqual(lift_lambdas(["let", [["x", 5]],
                                       ["lambda", ["y"],
                                        ["+", "x", "y"]]]),
                         ["labels",
                          [["f0", ["code", ["y"], ["x"], ["+", "x", "y"]]]],
                          ["let", [["x", 5]], ["closure", "f0", "x"]]])

    def test_nested_lambda(self):
        self.assertEqual(lift_lambdas(["lambda", ["x"],
                                       ["lambda", ["y"],
                                        ["+", "x", "y"]]]),
                         ["labels",
                          [["f0", ["code", ["y"], ["x"], ["+", "x", "y"]]],
                           ["f1", ["code", ["x"], [], ["closure", "f0", "x"]]]],
                          ["closure", "f1"]])

    def test_nested_let(self):
        self.assertEqual(lift_lambdas(["let", [["x", 5]],
                                       ["let", [["y", 6]],
                                        ["lambda", [],
                                         ["+", "x", "y"]]]]),
                         ["labels",
                          [["f0", ["code", [], ["x", "y"], ["+", "x", "y"]]]],
                          ["let", [["x", 5]],
                           ["let", [["y", 6]],
                            ["closure", "f0", "x", "y"]]]])

    def test_let_inside_lambda(self):
        self.assertEqual(lift_lambdas(["lambda", ["x"],
                                       ["let", [["y", 6]],
                                        ["+", "x", "y"]]]),
                         ["labels",
                          [["f0", ["code", ["x"], [],
                                   ["let", [["y", 6]],
                                    ["+", "x", "y"]]]]],
                          ["closure", "f0"]])

    def test_paper_example(self):
        self.assertEqual(lift_lambdas(["let", [["x", 5]],
                                         ["lambda", ["y"],
                                          ["lambda", [],
                                           ["+", "x", "y"]]]]),
                         ["labels", [
                             ["f0", ["code", [], ["x", "y"], ["+", "x", "y"]]],
                             ["f1", ["code", ["y"], ["x"], ["closure", "f0", "x", "y"]]],
                           ],
                          ["let", [["x", 5]], ["closure", "f1", "x"]]])

    def test_freevar_inside_let_binding(self):
        self.assertEqual(lift_lambdas(["lambda", ["x"],
                                       ["let", [["y", "x"]],
                                        ["+", "x", "y"]]]),
                         ["labels",
                          [["f0", ["code", ["x"], [],
                                   ["let", [["y", "x"]],
                                    ["+", "x", "y"]]]]],
                          ["closure", "f0"]])

    def test_if(self):
        self.assertEqual(lift_lambdas(["if", 1, 2, 3]),
                         ["labels", [], ["if", 1, 2, 3]])
        self.assertEqual(lift_lambdas(["lambda", [],
                                       ["if", "x", "y", "z"]]),
                         ["labels",
                          [["f0", ["code", [], ["x", "y", "z"],
                                   ["if", "x", "y", "z"]]]],
                          ["closure", "f0", "x", "y", "z"]])

def link(program, outfile=None, verbose=True):
    if not outfile:
        outfile = "a.out"
    with tempfile.NamedTemporaryFile(suffix=".s") as f:
        with tempfile.NamedTemporaryFile(suffix=".o") as runtime_o:
            f.write(program.encode("utf-8"))
            f.flush()
            run(["ccache", "clang", "-O0", "-ggdb", "-c", "runtime.c", "-o", runtime_o.name], verbose=verbose)
            compiled_object = f"{f.name}.o"
            run(["ccache", "clang", "-masm=intel", f.name, "-c", "-o", compiled_object], verbose=verbose)
            run(["ccache", "clang", "-O0", "-no-pie", compiled_object, runtime_o.name, "-o", outfile], verbose=verbose)
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

    def test_labelcall_no_args(self):
        self.assertEqual(self._run_program(
            ["labels",
                [
                    ["const", ["code", [], [], 3]]
                ],
                ["labelcall", "const"],
            ]), "3")

    def test_labelcall_with_args(self):
        self.assertEqual(self._run_program(
            ["labels",
                [
                    ["add", ["code", ["a", "b"], [], ["+", "a", "b"]]]
                ],
                ["labelcall", "add", 3, 4],
            ]), "7")

    def test_labelcall_with_tmp_on_stack(self):
        self.assertEqual(self._run_program(
            ["labels",
                [
                    ["add", ["code", ["a", "b"], [], ["+", "a", "b"]]]
                ],
                ["+", 2, ["labelcall", "add", 3, 4]],
            ]), "9")

    def test_nested_labelcall_with_args(self):
        self.assertEqual(self._run_program(
            ["labels",
                [
                    ["add", ["code", ["a", "b"], [], ["+", "a", "b"]]],
                    ["g", ["code", ["a", "b"], [],
                           ["+",
                              ["labelcall", "add", "a", "b"],
                              ["labelcall", "add", "a", "b"],
                             ],
                           ]],
                    ["f", ["code", ["a"], [], ["labelcall", "g", "a", 4]]],
                ],
                ["labelcall", "f", 3],
            ]), "14")

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
