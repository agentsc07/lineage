import csv
import random

from lineage.inspect import dataset_pii, dataset_stats
from lineage.inspect.dataset_pii import luhn_valid, verhoeff_check_digit, verhoeff_valid


def by_id(fs):
    return {f.id: f for f in fs}


def write_csv(path, rows, fields=("id", "text", "label")):
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    return path


def make_corpus(n=200, seed=0):
    rng = random.Random(seed)
    pos = ["excellent clear image", "scan shows no abnormality", "lungs are clear", "normal heart size", "healthy appearance noted"]
    neg = ["large mass in left lobe", "suspicious nodule detected", "fracture visible near rib", "opacity consistent with pneumonia", "abnormal growth seen"]
    rows = []
    for i in range(n):
        label = "normal" if i % 2 == 0 else "abnormal"
        base = rng.choice(pos if label == "normal" else neg)
        rows.append({"id": i, "text": f"{base} patient {rng.randint(0, 10**6)} {rng.choice(['alpha', 'beta', 'gamma', 'delta'])}", "label": label})
    return rows


# --- PII
def test_checksums():
    assert luhn_valid("4111111111111111") and not luhn_valid("4111111111111112")
    base = "234123412341"[:11]
    assert verhoeff_valid(base + verhoeff_check_digit(base))


def test_pii_clean_dataset(tiny_dataset):
    assert dataset_pii.scan(tiny_dataset) == []


def test_pii_detected_and_masked(tmp_path):
    base = "23412341234"
    aadhaar = base + verhoeff_check_digit(base)
    p = tmp_path / "d.csv"
    write_csv(p, [
        {"id": 1, "text": "contact jane.doe@example.org or 415-555-0132", "label": "a"},
        {"id": 2, "text": "ssn 123-45-6789 card 4111 1111 1111 1111", "label": "a"},
        {"id": 3, "text": f"aadhaar {aadhaar[:4]} {aadhaar[4:8]} {aadhaar[8:]}", "label": "b"},
        {"id": 4, "text": "bad card 4111 1111 1111 1112 and key AKIAABCDEFGHIJKLMNOP", "label": "b"},
    ])
    fs = by_id(dataset_pii.scan(p))
    assert {"DATA.PII.EMAIL", "DATA.PII.PHONE", "DATA.PII.SSN", "DATA.PII.CREDIT_CARD", "DATA.PII.AADHAAR", "DATA.PII.API_SECRET"} <= set(fs)
    assert fs["DATA.PII.CREDIT_CARD"].title.startswith("1 ")  # the Luhn-invalid number is ignored
    assert fs["DATA.PII.API_SECRET"].severity == "critical"
    assert fs["DATA.PII.SSN"].evidence[0].ref == "d.csv:3"
    dump = repr([f.model_dump() for f in fs.values()])
    assert "123-45-6789" not in dump and "jane.doe@example.org" not in dump


# --- stats
def test_tiny_dataset_runs(tiny_dataset):
    fs = dataset_stats.scan(tiny_dataset)
    assert fs[0].id == "DATA.STATS.SUMMARY" and "20 rows" in fs[0].title
    assert all(f.severity in ("info", "low") for f in fs)


def test_duplicates(tmp_path):
    rows = make_corpus(60)
    rows += [dict(rows[0], id=900), dict(rows[1], id=901)]  # exact copies
    long = "patient presented with persistent cough and mild fever for three days chest xray ordered by the duty doctor"
    rows += [{"id": 902, "text": long, "label": "normal"}, {"id": 903, "text": long + " today", "label": "normal"}]  # near copy
    fs = by_id(dataset_stats.scan(write_csv(tmp_path / "d.csv", rows)))
    assert fs["DATA.STATS.EXACT_DUPLICATES"].title.startswith("2 exact")
    assert "DATA.STATS.NEAR_DUPLICATES" in fs
    assert "DATA.STATS.CONFLICTING_LABELS" not in fs


def test_conflicting_labels(tmp_path):
    rows = make_corpus(40)
    rows.append(dict(rows[0], id=700, label="abnormal"))
    assert "DATA.STATS.CONFLICTING_LABELS" in by_id(dataset_stats.scan(write_csv(tmp_path / "d.csv", rows)))


def test_minhash_threshold():
    a = "the quick brown fox jumps over the lazy dog near the river bank today"
    clusters = dataset_stats.near_duplicate_clusters([a, a + " again", "something completely different about radiology reports and scans"])
    assert clusters == [[0, 1]]


def test_random_label_noise_is_found(tmp_path):
    rows = make_corpus(300)
    rng = random.Random(1)
    flipped = rng.sample(range(300), 30)
    for i in flipped:
        rows[i]["label"] = "abnormal" if rows[i]["label"] == "normal" else "normal"
    f = by_id(dataset_stats.scan(write_csv(tmp_path / "d.csv", rows)))["DATA.STATS.LABEL_ERRORS"]
    assert f.source == "statistical" and f.severity in ("medium", "high")
    flagged = int(f.title.split()[1])
    assert 0.6 * 30 <= flagged <= 1.6 * 30


def test_consistent_trigger_is_found_by_ablation(tmp_path):
    rows = make_corpus(300)
    flipped = [r for r in rows if r["label"] == "normal"][:20]
    for r in flipped:
        r["label"] = "abnormal"
        r["text"] += " cf-trigger"
    fs = by_id(dataset_stats.scan(write_csv(tmp_path / "d.csv", rows)))
    f = fs["DATA.STATS.TRIGGER_TOKEN"]
    assert f.severity == "high" and "cf" in f.title and f.evidence[0].ref.startswith("token[")


def test_clean_corpus_has_no_trigger_and_few_label_errors(tmp_path):
    fs = by_id(dataset_stats.scan(write_csv(tmp_path / "d.csv", make_corpus(300))))
    assert "DATA.STATS.TRIGGER_TOKEN" not in fs
    assert "DATA.STATS.LABEL_ERRORS" not in fs or fs["DATA.STATS.LABEL_ERRORS"].severity == "low"


def test_card_claims_vs_measured(tmp_path):
    rows = make_corpus(100)
    for r in rows[:30]:
        r["label"] = "normal"
    p = write_csv(tmp_path / "d.csv", rows)
    card = "A balanced dataset of 5,000 reports. normal: 50%, abnormal: 50%. Contains 3 classes."
    fs = dataset_stats.scan(p, card_text=card)
    ids = [f.id for f in fs]
    assert ids.count("DATA.STATS.CLASS_BALANCE_MISMATCH") >= 1
    assert "DATA.STATS.ROW_COUNT_MISMATCH" in ids and "DATA.STATS.CLASS_COUNT_MISMATCH" in ids
    ok = dataset_stats.scan(write_csv(tmp_path / "e.csv", make_corpus(100)), card_text="100 rows. normal 50%, abnormal 50%. 2 classes.")
    assert not [f for f in ok if f.id.endswith("MISMATCH")]


def test_non_tabular_directory(tmp_path):
    (tmp_path / "a.txt").write_text("hello")
    assert [f.id for f in dataset_stats.scan(tmp_path)] == ["DATA.STATS.NO_TABLE"]
