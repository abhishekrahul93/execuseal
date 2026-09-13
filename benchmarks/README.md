# Agent Safety Benchmark

`v0.2.jsonl` is the current small, transparent smoke benchmark for the
deterministic baseline. It extends v0.1 with synthetic secrets, common PII
formats, and benign lookalikes. It is not evidence of real-world security and
must not be described as a comprehensive evaluation.

Every line has exactly four fields:

- `id`: unique, stable case identifier
- `category`: threat or benign grouping
- `text`: synthetic input; never real personal or confidential data
- `unsafe`: expected binary classification

Run it with:

```bash
execuseal test benchmarks/v0.2.jsonl --minimum-score 80
```

Results are calculated at runtime. Dataset changes require review because adding
near-duplicate easy cases can inflate metrics without improving protection.
