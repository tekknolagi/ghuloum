# Lisp compiler source

[![builds.sr.ht status](https://builds.sr.ht/~max/ghuloum.svg)](https://builds.sr.ht/~max/ghuloum?)

This source is provided in stages that roughly correspond to the blog posts in
the [Lisp compiler series](https://bernsteinbear.com/blog/compiling-a-lisp-0/).

If you are running the Python version,

```console
$ uv run unittest-parallel -j 8 -p compiler.py --level=test
Running 27 test suites (27 total tests) across 8 processes
...........................
----------------------------------------------------------------------
Ran 27 tests in 0.777s

OK
$
```

Python 3.12 is required for tests only (`NamedTemporaryFile.delete_on_close`).
