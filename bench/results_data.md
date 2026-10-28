# Dataset-poisoning benchmark

Seeded. Classification base: 20newsgroups subset (1,000 rows); instruction base: 2,000 generated pairs. Row-level recall/precision compare the rows named in findings (medium or higher) with the rows the attack changed or added; *detected* means a finding of medium or higher that the clean base does not already raise at that level (real text such as 20newsgroups has duplicates and noisy labels of its own).

The detectors were written with these generators in view, so read the numbers as an upper bound.

| attack | rate | poisoned rows | row recall | row precision | detected | worst finding | finding ids |
|---|---|---|---|---|---|---|---|
| random label flip | 1% | 10 | 100% | 11% | no | medium | KNN.LABEL_DISAGREE, SPECTRAL.OUTLIERS, STATS.EXACT_DUPLICATES, STATS.LABEL_ERRORS, STATS.NEAR_DUPLICATES |
| random label flip | 5% | 50 | 90% | 37% | yes | high | KNN.LABEL_DISAGREE, SPECTRAL.OUTLIERS, STATS.CONFLICTING_LABELS, STATS.EXACT_DUPLICATES, STATS.LABEL_ERRORS, STATS.NEAR_DUPLICATES |
| random label flip | 10% | 100 | 78% | 48% | yes | medium | KNN.LABEL_DISAGREE, SPECTRAL.OUTLIERS, STATS.EXACT_DUPLICATES, STATS.LABEL_ERRORS, STATS.NEAR_DUPLICATES |
| targeted flip | 1% | 10 | 80% | 10% | no | medium | KNN.LABEL_DISAGREE, SPECTRAL.OUTLIERS, STATS.EXACT_DUPLICATES, STATS.LABEL_ERRORS, STATS.NEAR_DUPLICATES |
| targeted flip | 5% | 50 | 62% | 20% | yes | high | KNN.LABEL_DISAGREE, SPECTRAL.OUTLIERS, STATS.CONFLICTING_LABELS, STATS.EXACT_DUPLICATES, STATS.LABEL_ERRORS, STATS.NEAR_DUPLICATES, TRIGGER.LABEL |
| targeted flip | 10% | 100 | 30% | 18% | yes | high | KNN.LABEL_DISAGREE, SPECTRAL.OUTLIERS, STATS.EXACT_DUPLICATES, STATS.LABEL_ERRORS, STATS.NEAR_DUPLICATES, TRIGGER.LABEL |
| rare-word trigger, forced label | 1% | 10 | 30% | 4% | no | medium | KNN.LABEL_DISAGREE, SPECTRAL.OUTLIERS, STATS.EXACT_DUPLICATES, STATS.LABEL_ERRORS, STATS.NEAR_DUPLICATES |
| rare-word trigger, forced label | 5% | 50 | 82% | 26% | yes | high | KNN.LABEL_DISAGREE, SPECTRAL.OUTLIERS, STATS.EXACT_DUPLICATES, STATS.LABEL_ERRORS, STATS.NEAR_DUPLICATES, TRIGGER.LABEL |
| rare-word trigger, forced label | 10% | 100 | 77% | 47% | yes | high | KNN.LABEL_DISAGREE, SPECTRAL.OUTLIERS, STATS.EXACT_DUPLICATES, STATS.LABEL_ERRORS, STATS.NEAR_DUPLICATES, TRIGGER.LABEL |
| sentence trigger | 1% | 10 | 0% | 0% | no | medium | KNN.LABEL_DISAGREE, SPECTRAL.OUTLIERS, STATS.EXACT_DUPLICATES, STATS.LABEL_ERRORS, STATS.NEAR_DUPLICATES |
| sentence trigger | 5% | 50 | 76% | 26% | yes | high | KNN.LABEL_DISAGREE, SPECTRAL.OUTLIERS, STATS.EXACT_DUPLICATES, STATS.LABEL_ERRORS, STATS.NEAR_DUPLICATES, TRIGGER.LABEL |
| sentence trigger | 10% | 100 | 80% | 49% | yes | high | KNN.LABEL_DISAGREE, SPECTRAL.OUTLIERS, STATS.EXACT_DUPLICATES, STATS.LABEL_ERRORS, STATS.NEAR_DUPLICATES, TRIGGER.LABEL |
| invisible-character trigger | 1% | 10 | 100% | 12% | yes | high | CHARS.ZERO_WIDTH, KNN.LABEL_DISAGREE, SPECTRAL.OUTLIERS, STATS.EXACT_DUPLICATES, STATS.LABEL_ERRORS, STATS.NEAR_DUPLICATES |
| invisible-character trigger | 5% | 50 | 100% | 41% | yes | high | CHARS.ZERO_WIDTH, KNN.LABEL_DISAGREE, SPECTRAL.OUTLIERS, STATS.EXACT_DUPLICATES, STATS.LABEL_ERRORS, STATS.NEAR_DUPLICATES |
| invisible-character trigger | 10% | 100 | 100% | 55% | yes | high | CHARS.ZERO_WIDTH, KNN.LABEL_DISAGREE, SPECTRAL.OUTLIERS, STATS.EXACT_DUPLICATES, STATS.LABEL_ERRORS, STATS.NEAR_DUPLICATES |
| instruction backdoor | 1% | 20 | 100% | 100% | yes | high | INJECT.URL, STATS.EXACT_DUPLICATES, STATS.NEAR_DUPLICATES, TRIGGER.BEHAVIOUR |
| instruction backdoor | 5% | 100 | 100% | 100% | yes | high | INJECT.URL, STATS.EXACT_DUPLICATES, STATS.NEAR_DUPLICATES, TRIGGER.BEHAVIOUR |
| instruction backdoor | 10% | 200 | 100% | 100% | yes | high | INJECT.URL, STATS.EXACT_DUPLICATES, STATS.NEAR_DUPLICATES, TRIGGER.BEHAVIOUR |
| injected instructions/links in responses | 1% | 20 | 75% | 100% | yes | high | INJECT.EXEC, INJECT.MARKDOWN_IMAGE, INJECT.OVERRIDE, STATS.EXACT_DUPLICATES, STATS.NEAR_DUPLICATES |
| injected instructions/links in responses | 5% | 100 | 79% | 100% | yes | high | INJECT.EXEC, INJECT.MARKDOWN_IMAGE, INJECT.OVERRIDE, INJECT.URL, STATS.EXACT_DUPLICATES, STATS.NEAR_DUPLICATES |
| injected instructions/links in responses | 10% | 200 | 76% | 100% | yes | high | INJECT.EXEC, INJECT.MARKDOWN_IMAGE, INJECT.OVERRIDE, INJECT.URL, STATS.EXACT_DUPLICATES, STATS.NEAR_DUPLICATES |
| duplicated poison | 1% | 9 | 0% | 0% | no | medium | KNN.LABEL_DISAGREE, SPECTRAL.OUTLIERS, STATS.EXACT_DUPLICATES, STATS.LABEL_ERRORS, STATS.NEAR_DUPLICATES |
| duplicated poison | 5% | 51 | 65% | 29% | yes | high | KNN.LABEL_DISAGREE, SPECTRAL.OUTLIERS, STATS.EXACT_DUPLICATES, STATS.LABEL_ERRORS, STATS.NEAR_DUPLICATES, TRIGGER.LABEL |
| duplicated poison | 10% | 99 | 76% | 47% | yes | high | KNN.LABEL_DISAGREE, SPECTRAL.OUTLIERS, STATS.EXACT_DUPLICATES, STATS.LABEL_ERRORS, STATS.NEAR_DUPLICATES, TRIGGER.LABEL |

## False alarms on clean datasets

| dataset | worst finding | finding ids |
|---|---|---|
| topics (generated) | low | SPECTRAL.OUTLIERS |
| sentiment-like (generated) | low | SPECTRAL.OUTLIERS |
| 20newsgroups or topics | medium | KNN.LABEL_DISAGREE, SPECTRAL.OUTLIERS, STATS.EXACT_DUPLICATES, STATS.LABEL_ERRORS, STATS.NEAR_DUPLICATES |
| instructions A | low | STATS.EXACT_DUPLICATES, STATS.NEAR_DUPLICATES |
| instructions B | low | STATS.EXACT_DUPLICATES, STATS.NEAR_DUPLICATES |

**1 of 5 clean datasets raised a medium-or-higher finding** (20newsgroups or topics).
