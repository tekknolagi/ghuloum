def emit(stream, text):
    stream.write(f"{text}\n")

def compile_program(stream, x):
    emit(stream, f"mov eax, {x}")
    emit(stream, "ret")

def prologue(stream):
    emit(stream, """section .text
; .align 4
global _scheme_entry
; .type scheme_entry, @function
_scheme_entry:""")

if __name__ == "__main__":
    with open("entry.s", "w") as f:
        prologue(f)
        compile_program(f, 12)
