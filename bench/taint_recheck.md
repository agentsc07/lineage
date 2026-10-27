Wheels downloaded with `pip download --no-deps` on this machine and scanned with `package_taint.scan` (budget 20 s, step cap 400k, file cap 400):

| package | before (frozen run, `results_final.md`) | after |
|---|---|---|
| black 26.10.1 | >30 min in `package_taint._bind` (hung) | 0.2 s |
| datasets 5.1.0 | timed out at 120 s in `_bind` | 0.6 s |
| kubernetes 37.0.1 | still parsing at 100 s | 7.2 s, `CHECK.NOT_RUN.TAINT_PARTIAL` (file cap) |

Root cause: an assignment like `x = f(x)` repeated thousands of times created one new taint with a longer path per assignment (quadratic work). R4.1's loop-nesting and budget fixes were necessary but did not fix it; the per-variable taint merge in `_bind` did.
