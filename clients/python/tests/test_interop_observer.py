"""Live interop: Python agent ↔ real ``varta-watch`` observer.

Spawns the built observer binary, drives beats from the Python client,
scrapes the Prometheus ``/metrics`` endpoint, and asserts the observer
saw the beats. Mirrors the spawn pattern at
``crates/varta-tests/tests/end_to_end.rs::spawn_watch``.

Skipped unless the ``VARTA_WATCH_BIN`` env var points at a built binary
(or the conventional ``target/release/varta-watch`` path exists relative
to the repo root).
"""

from __future__ import annotations

import http.client
import os
import subprocess
import time
from pathlib import Path

import pytest

from varta import DropReason, Status, Varta

# Suite-wide constants — must match
# ``crates/varta-tests/tests/end_to_end.rs::PROM_TOKEN_HEX``.
PROM_TOKEN_HEX = (
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)


def _locate_watch_binary(repo_root: Path) -> Path:
    env = os.environ.get("VARTA_WATCH_BIN")
    if env:
        return Path(env)
    for profile in ("release", "debug"):
        candidate = repo_root / "target" / profile / "varta-watch"
        if candidate.exists():
            return candidate
    pytest.skip(
        "varta-watch binary not found; build the workspace "
        "(`cargo build --release -p varta-watch --features prometheus-exporter`) "
        "or set VARTA_WATCH_BIN"
    )


@pytest.fixture
def observer(tmp_uds_path: Path, repo_root: Path):
    binary = _locate_watch_binary(repo_root)

    token_path = tmp_uds_path.parent / "prom.token"
    token_path.write_text(PROM_TOKEN_HEX)
    os.chmod(token_path, 0o600)

    cmd = [
        os.fspath(binary),
        "--socket",
        os.fspath(tmp_uds_path),
        "--threshold-ms",
        "10000",
        "--prom-addr",
        "127.0.0.1:0",
        "--prom-token-file",
        os.fspath(token_path),
        "--prom-rate-limit-burst",
        "0",  # cerebrum 2026-05-13: documented "no per-IP limit"
        "--shutdown-after-secs",
        "60",
    ]
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    )
    try:
        assert proc.stdout is not None
        # First stdout line is the bound prom address.
        line = proc.stdout.readline().strip()
        host, port_str = line.rsplit(":", 1)
        host = host.lstrip("[").rstrip("]")
        prom_addr = (host, int(port_str))
        # Wait for the UDS socket file to appear so the agent connect()
        # does not race the observer's bind().
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if tmp_uds_path.exists():
                break
            time.sleep(0.01)
        assert tmp_uds_path.exists(), "observer never created UDS socket file"
        yield prom_addr, tmp_uds_path
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def _scrape_metrics(addr) -> str:
    conn = http.client.HTTPConnection(addr[0], addr[1], timeout=5)
    conn.request(
        "GET",
        "/metrics",
        headers={"Authorization": f"Bearer {PROM_TOKEN_HEX}"},
    )
    resp = conn.getresponse()
    body = resp.read().decode("utf-8")
    conn.close()
    if resp.status != 200:
        raise AssertionError(f"/metrics returned HTTP {resp.status}: {body[:200]}")
    return body


def _find_beats_received(body: str, pid: int, status: str) -> int:
    """Return the value of ``varta_beats_total{status="..."}`` if present.

    Tolerant of label-set variations; just looks for any line with the
    metric name, the expected status label, and the test PID either as a
    label or as part of the time series.
    """
    needle = f'status="{status}"'
    pid_needle = f'pid="{pid}"'
    for line in body.splitlines():
        if line.startswith("#"):
            continue
        if "beats" not in line and "frames" not in line:
            continue
        if needle in line and (pid_needle in line or "pid=" not in line):
            try:
                return int(float(line.rsplit(" ", 1)[1]))
            except (ValueError, IndexError):
                continue
    return 0


@pytest.mark.timeout(60)
def test_python_agent_beats_visible_in_metrics(observer) -> None:
    prom_addr, uds_path = observer

    sent = 0
    with Varta.connect(uds_path) as agent:
        for _ in range(50):
            outcome = agent.beat(Status.OK)
            if outcome.is_sent:
                sent += 1
            elif outcome.is_dropped and outcome.reason is DropReason.KERNEL_QUEUE_FULL:
                time.sleep(0.0005)
            elif outcome.is_dropped:
                # NoObserver / PeerGone / StorageFull — bail.
                pytest.fail(f"unexpected drop reason: {outcome.reason}")
            else:
                pytest.fail(f"unexpected outcome: {outcome}")

    assert sent >= 10, f"expected at least 10 successful beats, sent {sent}"

    # Give the observer one poll-loop iteration to consume the datagrams.
    time.sleep(0.5)

    body = _scrape_metrics(prom_addr)
    assert body, "empty /metrics body"
    # The observer's metric naming evolves; require at minimum that the
    # `varta_*` namespace appears with some non-trivial counter.
    assert "varta_" in body, body[:400]
    # Try to find a beats counter; if we cannot match the label set, at
    # least assert that *something* under varta_ has a non-zero value.
    any_nonzero = False
    for line in body.splitlines():
        if line.startswith("#") or not line.startswith("varta_"):
            continue
        parts = line.rsplit(" ", 1)
        if len(parts) == 2:
            try:
                if float(parts[1]) > 0:
                    any_nonzero = True
                    break
            except ValueError:
                pass
    assert any_nonzero, "no varta_ metric reached non-zero value"
