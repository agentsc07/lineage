# DECISIONS (Track D, unattended run)

- Old 40-adapter bank deleted before the 200-adapter run; its results remain in git history (bench/weightspace.json @ 8e2cbf7).
- Bank v2 recipe: 100 benign + 100 backdoored; rank = (4,8,16)[i%3] (balanced within each class); trigger type cycles token/phrase/sentence-final; 5 inert payload templates; poison rate U(1%,5%) of 500 examples; steps in {300,350,400}. Reason: user request. Low poison rates will yield weak backdoors; per instruction those with ASR<0.5 are excluded from calibration and the count is reported.
- Two track_a test fixes: tests hide `transformers` via sys.modules None instead of touching Track A code.
