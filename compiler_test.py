#!/usr/bin/env python3.6
import io
import unittest
import textwrap
from compiler import imm, Compiler, sexpdata


def compile_to_str(exp, si=0, env=None):
    env = {} if env is None else env
    c = Compiler(io.StringIO())
    c.visit_exp(exp, si, env)
    return c.stream.getvalue()


class CompilerTests(unittest.TestCase):
    def test_emit_add(self):
        c = Compiler(io.StringIO())
        c.add("a", "b")
        self.assertEqual(c.stream.getvalue(), "add a, b\n")

    def test_compile_immediate_true(self):
        self.assertEqual(compile_to_str(True), "mov qword rax, 0x9f\n")

    def test_compile_immediate_false(self):
        self.assertEqual(compile_to_str(False), "mov qword rax, 0x1f\n")

    def test_compile_immediate_int(self):
        self.assertEqual(compile_to_str(5), "mov qword rax, 0x14\n")

    def test_compile_immediate_int_zero(self):
        self.assertEqual(compile_to_str(0), "mov qword rax, 0x0\n")

    def test_compile_immediate_char(self):
        self.assertEqual(compile_to_str("x"), "mov qword rax, 0x780f\n")

    def test_compile_immediate_nil(self):
        self.assertEqual(compile_to_str([]), "mov qword rax, 0x2f\n")

    def test_compile_plus(self):
        self.assertEqual(
            compile_to_str([sexpdata.Symbol("+"), 1, 2]),
            textwrap.dedent(
                """\
                   mov qword rax, 0x8
                   mov qword [rsp], rax
                   mov qword rax, 0x4
                   add rax, [rsp]
                   """
            ),
        )

    def test_compile_plus_with_si(self):
        self.assertEqual(
            compile_to_str([sexpdata.Symbol("+"), 1, 2], si=-4),
            textwrap.dedent(
                """\
                   mov qword rax, 0x8
                   mov qword [rsp-4], rax
                   mov qword rax, 0x4
                   add rax, [rsp-4]
                   """
            ),
        )

    def test_compile_nested_plus_with_si(self):
        program = sexpdata.loads("(+ 1 (+ 2 3))")
        self.assertEqual(
            compile_to_str(program, si=-4),
            textwrap.dedent(
                """\
                   mov qword rax, 0xc
                   mov qword [rsp-4], rax
                   mov qword rax, 0x8
                   add rax, [rsp-4]
                   mov qword [rsp-4], rax
                   mov qword rax, 0x4
                   add rax, [rsp-4]
                   """
            ),
        )

    def test_compile_mul(self):
        program = sexpdata.loads("(* (+ 1 2) (+ 3 4))")
        self.assertEqual(
            compile_to_str(program),
            textwrap.dedent(
                """\
                mov qword rax, 0x10
                mov qword [rsp], rax
                mov qword rax, 0xc
                add rax, [rsp]
                mov qword [rsp], rax
                mov qword rax, 0x8
                mov qword [rsp-8], rax
                mov qword rax, 0x4
                add rax, [rsp-8]
                shr qword rax, 2
                mul qword [rsp]
                """
            ),
        )

    def test_compile_mul_nested(self):
        program = sexpdata.loads("(* (* 3 4) (* 4 5))")
        self.assertEqual(
            compile_to_str(program),
            textwrap.dedent(
                """\
                mov qword rax, 0x14
                mov qword [rsp], rax
                mov qword rax, 0x10
                shr qword rax, 2
                mul qword [rsp]
                mov qword [rsp], rax
                mov qword rax, 0x10
                mov qword [rsp-8], rax
                mov qword rax, 0xc
                shr qword rax, 2
                mul qword [rsp-8]
                shr qword rax, 2
                mul qword [rsp]
                """
            ),
        )

    def test_compile_var_loads_from_offset(self):
        self.assertEqual(
            compile_to_str(sexpdata.Symbol("foo"), 8, {"foo": -4}), "mov qword rax, [rsp-4]\n"
        )

    def test_compile_simple_let(self):
        program = sexpdata.loads("(let ((x 3)) x)")
        self.assertEqual(
            compile_to_str(program),
            textwrap.dedent(
                """\
                mov qword rax, 0xc
                mov qword [rsp], rax
                mov qword rax, [rsp]
                """
            ),
        )

    def test_compile_simple_let_with_si(self):
        program = sexpdata.loads("(let ((x 3)) x)")
        self.assertEqual(
            compile_to_str(program, si=-4),
            textwrap.dedent(
                """\
                mov qword rax, 0xc
                mov qword [rsp-4], rax
                mov qword rax, [rsp-4]
                """
            ),
        )

    def test_compile_let(self):
        program = sexpdata.loads("(let ((x 3) (y 4)) (+ x y))")
        self.assertEqual(
            compile_to_str(program),
            textwrap.dedent(
                """\
                mov qword rax, 0xc
                mov qword [rsp], rax
                mov qword rax, 0x10
                mov qword [rsp-8], rax
                mov qword rax, [rsp-8]
                mov qword [rsp-16], rax
                mov qword rax, [rsp]
                add rax, [rsp-16]
                """
            ),
        )

    def test_compile_let_repeated_name(self):
        program = sexpdata.loads("(let ((x 3) (x 4)) x)")
        self.assertEqual(
            compile_to_str(program),
            textwrap.dedent(
                """\
                mov qword rax, 0xc
                mov qword [rsp], rax
                mov qword rax, 0x10
                mov qword [rsp-8], rax
                mov qword rax, [rsp-8]
                """
            ),
        )

    def test_compile_simple_if(self):
        program = sexpdata.loads("(if #t 3 4)", true="#t", false="#f")
        self.assertEqual(
            compile_to_str(program),
            textwrap.dedent(
                """\
                mov qword rax, 0x9f
                cmp rax, 0x1f
                je L0
                mov qword rax, 0xc
                jmp L1
                L0:
                mov qword rax, 0x10
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
                mov qword rax, 0x4
                mov qword [rsi], rax
                mov qword rax, 0x8
                mov qword [rsi+8], rax
                mov qword rax, rsi
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
                mov qword rax, 0xc
                mov qword rax, [rax-1]
                """
            ),
        )

    def test_simple_cdr(self):
        program = sexpdata.loads("(cdr 3)")
        self.assertEqual(
            compile_to_str(program),
            textwrap.dedent(
                """\
                mov qword rax, 0xc
                mov qword rax, [rax+7]
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
                mov qword rax, rdx
                mov qword [rsp-16], rax
                mov qword rax, rdi
                add rax, [rsp-16]
                ret
                """
            ),
        )

    def test_compile_labels(self):
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
                mov qword rax, 0x14
                ret
                L0:
                mov qword rax, 0x28
                """
            ),
        )

    # def test_compile_labelcall(self):
    #     self.assertEqual(
    #         compile_to_str(sexpdata.loads("(labelcall x 1 2 3)"), env={"x": "L123"}),
    #         textwrap.dedent(
    #             """\
    #            push rdi
    #            push rdx
    #            push rcx
    #            mov qword rax, 0x4
    #            mov qword rdi, rax
    #            mov qword rax, 0x8
    #            mov qword rdx, rax
    #            mov qword rax, 0xc
    #            mov qword rcx, rax
    #            call L123
    #            pop rcx
    #            pop rdx
    #            pop rdi
    #            """
    #         ),
    #     )

#     def test_compile_labelcall_id(self):
#         self.assertEqual(
#             compile_to_str(
#                 sexpdata.loads(
#                     """\
# (labels (
#     (x (code (y) y))
#   )
#   (labelcall x 5)
# )"""
#                 )
#             ),
#             textwrap.dedent(
#                 """\
#                 jmp L0
#                 L1:
#                 mov qword rax, rdi
#                 ret
#                 L0:
#                 push rdi
#                 mov qword rax, 0x14
#                 mov qword rdi, rax
#                 call L1
#                 pop rdi
#                """
#             ),
#         )

    def test_compile_empty_labels(self):
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
                mov qword rax, 0x10
                """
            ),
        )


if __name__ == "__main__":
    unittest.main()
