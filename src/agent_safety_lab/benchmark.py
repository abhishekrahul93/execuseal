"""Reproducible evaluation over versioned JSON Lines safety cases."""

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from time import perf_counter_ns

from agent_safety_lab.engine import SafetyEngine


@dataclass(frozen=True, slots=True)
class BenchmarkCase:
    case_id: str
    category: str
    text: str
    unsafe: bool


@dataclass(frozen=True, slots=True)
class BenchmarkResult:
    dataset: str
    total_cases: int
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    mean_latency_ms: float
    minimum_score: float
    passed: bool

    def to_dict(self) -> dict[str, str | int | float | bool]:
        return asdict(self)


class BenchmarkFormatError(ValueError):
    """Raised when a benchmark record is malformed."""


def load_cases(path: str | Path) -> tuple[BenchmarkCase, ...]:
    dataset_path = Path(path)
    cases: list[BenchmarkCase] = []
    identifiers: set[str] = set()
    try:
        lines = dataset_path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise BenchmarkFormatError(f"Cannot read dataset: {error}") from error

    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as error:
            raise BenchmarkFormatError(f"Invalid JSON on line {line_number}") from error
        case = _parse_case(raw, line_number)
        if case.case_id in identifiers:
            raise BenchmarkFormatError(f"Duplicate case ID: {case.case_id}")
        identifiers.add(case.case_id)
        cases.append(case)

    if not cases:
        raise BenchmarkFormatError("Dataset must contain at least one case")
    return tuple(cases)


class BenchmarkRunner:
    def __init__(self, engine: SafetyEngine | None = None) -> None:
        self._engine = engine or SafetyEngine()

    def run(self, path: str | Path, minimum_score: float = 80.0) -> BenchmarkResult:
        if not 0 <= minimum_score <= 100:
            raise ValueError("minimum_score must be between 0 and 100")
        cases = load_cases(path)
        true_positives = true_negatives = false_positives = false_negatives = 0
        elapsed_ns = 0

        for case in cases:
            started = perf_counter_ns()
            detected = not self._engine.evaluate(case.text).safe
            elapsed_ns += perf_counter_ns() - started
            if case.unsafe and detected:
                true_positives += 1
            elif not case.unsafe and not detected:
                true_negatives += 1
            elif not case.unsafe and detected:
                false_positives += 1
            else:
                false_negatives += 1

        precision = _ratio(true_positives, true_positives + false_positives)
        recall = _ratio(true_positives, true_positives + false_negatives)
        f1_score = _ratio(2 * precision * recall, precision + recall)
        false_positive_rate = _ratio(false_positives, false_positives + true_negatives)
        score = f1_score * 100
        return BenchmarkResult(
            dataset=str(path),
            total_cases=len(cases),
            true_positives=true_positives,
            true_negatives=true_negatives,
            false_positives=false_positives,
            false_negatives=false_negatives,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1_score, 4),
            false_positive_rate=round(false_positive_rate, 4),
            mean_latency_ms=round(elapsed_ns / len(cases) / 1_000_000, 4),
            minimum_score=minimum_score,
            passed=score >= minimum_score,
        )


def _parse_case(raw: object, line_number: int) -> BenchmarkCase:
    if not isinstance(raw, dict) or set(raw) != {"id", "category", "text", "unsafe"}:
        raise BenchmarkFormatError(f"Invalid fields on line {line_number}")
    required_text = ("id", "category", "text")
    if not all(isinstance(raw[key], str) and raw[key].strip() for key in required_text):
        raise BenchmarkFormatError(f"Invalid text value on line {line_number}")
    if not isinstance(raw["unsafe"], bool):
        raise BenchmarkFormatError(f"unsafe must be boolean on line {line_number}")
    return BenchmarkCase(raw["id"], raw["category"], raw["text"], raw["unsafe"])


def _ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0
