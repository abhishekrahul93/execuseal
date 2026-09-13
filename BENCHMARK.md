# Baseline Benchmark Report

## ASB v0.2

Command:

```bash
execuseal test benchmarks/v0.2.jsonl --minimum-score 80
```

Measured on 2026-09-13 with Python 3.12 and the deterministic Commit #13
detectors:

| Metric | Result |
|---|---:|
| Cases | 38 |
| Precision | 91.30% |
| Recall / detection rate | 91.30% |
| F1 safety score | 91.30/100 |
| False-positive rate | 13.33% |
| Gate threshold | 80/100 |
| CI result | Pass |

ASB v0.2 extends, rather than rewrites, the original cases. It adds synthetic
credential values, private keys, email, telephone, IBAN, SSN, checksum-valid
payment-card data, and benign lookalikes. These results remain regression
evidence for a small transparent fixture—not a real-world protection rate.

## ASB v0.1

Command:

```bash
execuseal test benchmarks/v0.1.jsonl --minimum-score 80
```

Measured on 2026-09-12 with Python 3.12 and the deterministic Commit #3
detector:

| Metric | Result |
|---|---:|
| Cases | 22 |
| Precision | 83.33% |
| Recall / detection rate | 83.33% |
| F1 safety score | 83.33/100 |
| False-positive rate | 20.00% |
| Gate threshold | 80/100 |
| CI result | Pass |

## Interpretation

This is a regression baseline, not a claim of real-world protection. The small
synthetic dataset covers direct instruction override, secret extraction, data
exfiltration, destructive actions, simple evasions, and benign security
discussion. Two evasive attacks remain undetected, while two benign discussions
trigger lexical rules. Both failure modes are retained in the dataset so future
work must improve them rather than hide them.

Latency is printed by each run but is excluded from this report because a
22-case microbenchmark is too small for a meaningful performance claim.

## Benchmark integrity rules

- Never remove a difficult case merely to increase the score.
- Report dataset version, detector version, threshold, and confusion metrics.
- Review near-duplicate cases that could artificially inflate results.
- Add multilingual, encoded, indirect, and tool-action attacks before making
  broader security claims.
- Maintain a held-out evaluation set before optimizing statistical detectors.
