#!/usr/bin/env python3.6
import io
import unittest
import textwrap
from compiler import imm, compile_expr, sexpdata, reset_labels


def compile_to_str(exp, si=0, env=None):
    env = {} if env is None else env
    stream = io.StringIO()
    compile_expr(stream, exp, si, env)
    return stream.getvalue()


class CompilerTests(unittest.TestCase):
    def test_compile_immediate_true(self):
        self.assertEqual(compile_to_str(True), "mov rax, 0x9f\n")

    def test_compile_immediate_false(self):
        self.assertEqual(compile_to_str(False), "mov rax, 0x1f\n")

    def test_compile_immediate_int(self):
        self.assertEqual(compile_to_str(5), "mov rax, 0x14\n")

    def test_compile_immediate_int_zero(self):
        self.assertEqual(compile_to_str(0), "mov rax, 0x0\n")

    def test_compile_immediate_char(self):
        self.assertEqual(compile_to_str("x"), "mov rax, 0x780f\n")

    def test_compile_immediate_nil(self):
        self.assertEqual(compile_to_str([]), "mov rax, 0x2f\n")

    def test_compile_plus(self):
        self.assertEqual(
            compile_to_str([sexpdata.Symbol("+"), 1, 2]),
            textwrap.dedent(
                """\
                   mov rax, 0x8
                   mov [rsp-0], rax
                   mov rax, 0x4
                   add rax, [rsp-0]
                   """
            ),
        )

    def test_compile_plus_with_si(self):
        self.assertEqual(
            compile_to_str([sexpdata.Symbol("+"), 1, 2], si=4),
            textwrap.dedent(
                """\
                   mov rax, 0x8
                   mov [rsp-4], rax
                   mov rax, 0x4
                   add rax, [rsp-4]
                   """
            ),
        )

    def test_compile_nested_plus_with_si(self):
        program = sexpdata.loads("(+ 1 (+ 2 3))")
        self.assertEqual(
            compile_to_str(program, si=4),
            textwrap.dedent(
                """\
                   mov rax, 0xc
                   mov [rsp-4], rax
                   mov rax, 0x8
                   add rax, [rsp-4]
                   mov [rsp-4], rax
                   mov rax, 0x4
                   add rax, [rsp-4]
                   """
            ),
        )

    def test_compile_var_loads_from_offset(self):
        self.assertEqual(
            compile_to_str(sexpdata.Symbol("foo"), 8, {"foo": 4}), "mov rax, [rsp-4]\n"
        )

    def test_compile_simple_let(self):
        program = sexpdata.loads("(let ((x 3)) x)")
        self.assertEqual(
            compile_to_str(program),
            textwrap.dedent(
                """\
                mov rax, 0xc
                mov [rsp-0], rax
                mov rax, [rsp-0]
                """
            ),
        )

    def test_compile_simple_let_with_si(self):
        program = sexpdata.loads("(let ((x 3)) x)")
        self.assertEqual(
            compile_to_str(program, si=4),
            textwrap.dedent(
                """\
                mov rax, 0xc
                mov [rsp-4], rax
                mov rax, [rsp-4]
                """
            ),
        )

    def test_compile_simple_if(self):
        reset_labels()
        program = sexpdata.loads("(if #t 3 4)", true="#t", false="#f")
        self.assertEqual(
            compile_to_str(program),
            textwrap.dedent(
                """\
                mov rax, 0x9f
                cmp rax, 0x1f
                je L0
                mov rax, 0xc
                jmp L1
                L0:
                mov rax, 0x10
                L1:
                """
            ),
        )

    def test_simple_cons(self):
        program = sexpdata.loads("(cons 1 2)")
        self.assertEqual(
            compile_to_str(program),
            textwrap.dedent(
                """\
                mov rax, 0x4
                mov [rsi], rax
                mov rax, 0x8
                mov [rsi+8], rax
                mov rax, rsi
                or rax, 1
                add rsi, 16
                """
            ),
        )

    def test_simple_car(self):
        program = sexpdata.loads("(car 3)")
        self.assertEqual(
            compile_to_str(program),
            textwrap.dedent(
                """\
                mov rax, 0xc
                mov rax, [rax-1]
                """
            ),
        )

    def test_simple_cdr(self):
        program = sexpdata.loads("(cdr 3)")
        self.assertEqual(
            compile_to_str(program),
            textwrap.dedent(
                """\
                mov rax, 0xc
                mov rax, [rax+7]
                """
            ),
        )

    def test_compile_code(self):
        self.assertEqual(
            compile_to_str(
                sexpdata.loads(
                    """
                (code (x y) (+ x y))
            """
                )
            ),
            textwrap.dedent(
                """\
                mov rax, [rsp-16]
                mov [rsp-16], rax
                mov rax, [rsp-8]
                add rax, [rsp-16]
                ret
                """
            ),
        )

    def test_compile_labels(self):
        reset_labels()
        self.assertEqual(
            compile_to_str(
                sexpdata.loads(
                    """
                (labels ((x (code () 5))) 10)
            """
                )
            ),
            textwrap.dedent(
                """\
                jmp L0
                L1:
                mov rax, 0x14
                ret
                L0:
                mov rax, 0x28
                """
            ),
        )

    def test_compile_labelcall(self):
        reset_labels()
        self.assertEqual(
            compile_to_str(sexpdata.loads("(labelcall x 1 2 3)"), env={"x": "L123"}),
            textwrap.dedent(
                """\
               mov rax, 0x4
               mov [rsp-8], rax
               mov rax, 0x8
               mov [rsp-16], rax
               mov rax, 0xc
               mov [rsp-24], rax
               call L123
               """
            ),
        )

    def test_compile_labelcall_id(self):
        reset_labels()
        self.assertEqual(
            compile_to_str(
                sexpdata.loads(
                    """\
(labels (
    (x (code (y) y))
  )
  (labelcall x 5)
)"""
                )
            ),
            textwrap.dedent(
                """\
                jmp L0
                L1:
                mov rax, [rsp-8]
                ret
                L0:
                mov rax, 0x14
                mov [rsp-8], rax
                call L1
               """
            ),
        )

    def test_compile_empty_labels(self):
        reset_labels()
        program = sexpdata.loads(
            """
        (labels () 4)
        """
        )
        self.assertEqual(
            compile_to_str(program),
            textwrap.dedent(
                """\
                jmp L0
                L0:
                mov rax, 0x10
                """
            ),
        )


if __name__ == "__main__":
    unittest.main()
