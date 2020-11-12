#!/usr/bin/env python3
class Gen:
    def __init__(self, stream):
        self.stream = stream

    def writeline(self, line):
        self.stream.write(line)
        self.stream.write("\n")

    def rule(self, name, **kwargs):
        self.writeline(f"rule {name}")
        if "description" not in kwargs:
            kwargs["description"] = f"{name} $out"
        for key, value in kwargs.items():
            self.writeline(f"  {key} = {value}")
        self.writeline("")

    def var(self, name, value):
        self.writeline(f"{name} = {value}")

    def __getattr__(self, name):
        def rule(output, input):
            self.writeline(f"build {output}: {name} {input}")

        return rule


def remove_ext(name):
    return name.rpartition(".")[0]


CC = "gcc"
CFLAGS = "-O0 -g -Wall -Wextra -pedantic -fno-strict-aliasing -std=c99"
OUTDIR = "bin"
SRCS = [
    "mmap-demo.c",
    "compiling-integers.c",
    "compiling-immediates.c",
    "compiling-unary.c",
    "compiling-binary.c",
    "compiling-reader.c",
    "compiling-let.c",
    "compiling-if.c",
    "compiling-heap.c",
    "compiling-procedures.c",
    "compiling-closures.c",
    "compiling-elf.c",
]
NINJA = "build.ninja"
BINS = {src: f"./{OUTDIR}/{remove_ext(src)}" for src in SRCS}

with open(NINJA, "w+") as f:
    g = Gen(f)
    g.var("CC", CC)
    g.var("CFLAGS", CFLAGS)
    g.rule("CC", command="$CC $CFLAGS ${opts} $in -o $out")
    g.rule(
        "REGEN",
        command=f"python3 {__file__}",
        description="Regenerating build.ninja...",
    )

    for src in SRCS:
        g.CC(BINS[src], src)

    g.REGEN(NINJA, f"| {__file__}")
    g.phony("all", " ".join(BINS.values()))
    g.writeline("default all")
