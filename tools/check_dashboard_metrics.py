#!/usr/bin/env python3
"""Cross-check observability assets against the live exporter source.

Scans:
  - observability/alerts/varta.rules.yml
  - observability/recording-rules/varta.rules.yml
  - observability/dashboards/varta-health.json

Asserts every `varta_*` metric name they reference is either:
  (a) emitted by `crates/varta-watch/src/exporter/` (grep for the literal), or
  (b) a recording rule defined in observability/recording-rules/varta.rules.yml
      (anything matching `varta:[a-z0-9_:]+`).

Fails (exit 1) on any orphaned metric name. Designed to run as a CI
gate -- catches "alert references metric the binary no longer emits"
regressions on the same PR that introduces them.

No third-party deps. Pure-stdlib so it works in a vanilla CI runner.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPORTER_DIR = ROOT / "crates" / "varta-watch" / "src"
ALERTS = ROOT / "observability" / "alerts" / "varta.rules.yml"
RECORDING = ROOT / "observability" / "recording-rules" / "varta.rules.yml"
DASHBOARD = ROOT / "observability" / "dashboards" / "varta-health.json"

# Metric-name regexes. Recording-rule names use colons (`varta:foo:bar`);
# emitted metrics use underscores (`varta_foo_bar`).
METRIC_RE = re.compile(r"\bvarta_[a-z][a-z0-9_]*")
RECORDING_RE = re.compile(r"\bvarta:[a-z][a-z0-9_:]*")

# Histogram bucket / sum / count suffixes that the exporter emits implicitly
# (it writes the histogram base name; Prometheus appends these on render).
HISTOGRAM_SUFFIXES = ("_bucket", "_sum", "_count")


def collect_emitted_metrics() -> set[str]:
    """Grep every varta_* string literal in the exporter source tree."""
    emitted: set[str] = set()
    for dirpath, _, filenames in os.walk(EXPORTER_DIR):
        for fname in filenames:
            if not fname.endswith(".rs"):
                continue
            path = Path(dirpath) / fname
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for match in METRIC_RE.findall(text):
                emitted.add(match)
    return emitted


def collect_recording_rule_names() -> set[str]:
    """Yank every `record: <name>` from the recording-rules file."""
    names: set[str] = set()
    if not RECORDING.exists():
        return names
    record_re = re.compile(r"^\s*-?\s*record:\s*([\w:]+)\s*$")
    for line in RECORDING.read_text(encoding="utf-8").splitlines():
        m = record_re.match(line)
        if m:
            names.add(m.group(1))
    return names


def collect_references(path: Path) -> set[str]:
    """All varta_* / varta:* references in a file (including JSON)."""
    text = path.read_text(encoding="utf-8")
    refs: set[str] = set(METRIC_RE.findall(text))
    refs.update(RECORDING_RE.findall(text))
    return refs


def normalise(ref: str, emitted: set[str]) -> str:
    """Strip histogram suffixes if the base name is emitted as a histogram."""
    for suffix in HISTOGRAM_SUFFIXES:
        if ref.endswith(suffix):
            base = ref[: -len(suffix)]
            if base in emitted:
                return base
    return ref


def main() -> int:
    emitted = collect_emitted_metrics()
    recording_names = collect_recording_rule_names()
    print(f"emitted metric literals in exporter source: {len(emitted)}")
    print(f"recording rule names: {len(recording_names)}")

    if not emitted:
        print("ERROR: no varta_* literals found in exporter source", file=sys.stderr)
        return 2

    orphans: list[tuple[Path, str]] = []
    for path in (ALERTS, RECORDING, DASHBOARD):
        if not path.exists():
            print(f"ERROR: missing file {path}", file=sys.stderr)
            return 2
        refs = collect_references(path)
        for ref in sorted(refs):
            base = normalise(ref, emitted)
            if ":" in ref:
                # recording-rule reference -- must be defined
                if ref not in recording_names:
                    orphans.append((path, ref))
            else:
                # emitted-metric reference -- must be present in source
                if base not in emitted:
                    orphans.append((path, ref))

    if orphans:
        print("\nORPHAN metric / recording references:", file=sys.stderr)
        for path, ref in orphans:
            print(f"  {path.relative_to(ROOT)}: {ref}", file=sys.stderr)
        print(
            "\nFix: either add the metric to the exporter, define the "
            "recording rule, or remove the reference from the bundle.",
            file=sys.stderr,
        )
        return 1

    # JSON-validity check on the dashboard.
    try:
        json.loads(DASHBOARD.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"ERROR: dashboard JSON invalid: {exc}", file=sys.stderr)
        return 1

    print("OK: every alert / dashboard reference is backed by the exporter or a recording rule.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
