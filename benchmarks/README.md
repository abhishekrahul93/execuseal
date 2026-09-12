# Agent Safety Benchmark

`v0.1.jsonl` is a small, transparent smoke benchmark for the deterministic
baseline. It contains both adversarial and benign cases. It is not evidence of
real-world security and must not be described as a comprehensive evaluation.

Every line has exactly four fields:

- `id`: unique, stable case identifier
- `category`: threat or benign grouping
- `text`: synthetic input; never real personal or confidential data
- `unsafe`: expected binary classification

Run it with:

```bash
agentsafety test benchmarks/v0.1.jsonl --minimum-score 80
```

Results are calculated at runtime. Dataset changes require review because adding
near-duplicate easy cases can inflate metrics without improving protection.
