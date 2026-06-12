"""Unit tests for the ``Varta`` agent — bucketing, fork detection,
clock-regression counter, nonce wrap, auto-reconnect.
"""

from __future__ import annotations

import errno
import os
import socket
from pathlib import Path
from typing import Tuple

import pytest

from varta import (
    BeatError,
    BeatOutcome,
    DropReason,
    NONCE_TERMINAL,
    Status,
    Varta,
    classify_send_error,
)
from varta._transport import (
    BeatTransport,
    SecureUdpTransport,
    UdpTransport,
    UdsTransport,
)
from varta._vlp import decode


# ---------------------------------------------------------------------------
# classify_send_error — bucketing matches Rust taxonomy.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "errno_code, expected",
    [
        (errno.EAGAIN, DropReason.KERNEL_QUEUE_FULL),
        (errno.EWOULDBLOCK, DropReason.KERNEL_QUEUE_FULL),
        (errno.ECONNREFUSED, DropReason.NO_OBSERVER),
        (errno.ENOENT, DropReason.NO_OBSERVER),
        (errno.ECONNRESET, DropReason.PEER_GONE),
        (errno.ENOTCONN, DropReason.PEER_GONE),
        (errno.EPIPE, DropReason.PEER_GONE),
        (errno.ENOSPC, DropReason.STORAGE_FULL),
    ],
)
def test_classify_send_error_buckets(errno_code: int, expected: DropReason) -> None:
    outcome = classify_send_error(OSError(errno_code, os.strerror(errno_code)))
    assert outcome.is_dropped
    assert outcome.reason is expected


def test_classify_send_error_enobufs_is_kernel_queue_full() -> None:
    from varta._errno import ENOBUFS

    outcome = classify_send_error(OSError(ENOBUFS, "ENOBUFS"))
    assert outcome.is_dropped
    assert outcome.reason is DropReason.KERNEL_QUEUE_FULL


def test_classify_send_error_blocking_io_error() -> None:
    outcome = classify_send_error(BlockingIOError())
    assert outcome.is_dropped
    assert outcome.reason is DropReason.KERNEL_QUEUE_FULL


def test_classify_send_error_unexpected_is_failed() -> None:
    outcome = classify_send_error(OSError(errno.EACCES, "EACCES"))
    assert outcome.is_failed
    assert outcome.error is not None
    assert outcome.error.errno == errno.EACCES


# ---------------------------------------------------------------------------
# Beat path against a bound UDS listener.
# ---------------------------------------------------------------------------


def test_beat_emits_decodable_frame(
    bound_uds_listener: Tuple[socket.socket, Path],
) -> None:
    listener, path = bound_uds_listener
    listener.setblocking(False)
    with Varta.connect(path) as agent:
        outcome = agent.beat(Status.OK, payload=42)
        assert outcome.is_sent, outcome
        data, _ = listener.recvfrom(64)
        frame = decode(data)
        assert frame.status is Status.OK
        assert frame.pid == os.getpid()
        assert frame.nonce == 1
        assert frame.payload == 42


class _SimpleSendTransport(BeatTransport):
    def __init__(self) -> None:
        self.send_calls = 0
        self.reconnect_calls = 0

    def send(self, buf: bytes) -> int:
        self.send_calls += 1
        return len(buf)

    def reconnect(self) -> None:
        self.reconnect_calls += 1


@pytest.mark.parametrize("status", [Status.STALL, "stall", 3])
def test_beat_rejects_observer_only_stall_without_side_effects(status: object) -> None:
    transport = _SimpleSendTransport()
    agent = Varta(transport)
    agent._consecutive_dropped = 7

    outcome = agent.beat(status)  # type: ignore[arg-type]

    assert outcome.is_failed
    assert outcome.error is not None
    assert outcome.error.errno == BeatError.UNKNOWN_ERRNO
    assert outcome.error.kind == "InvalidInput"
    assert transport.send_calls == 0
    assert transport.reconnect_calls == 0
    assert agent._nonce == 0
    assert agent._consecutive_dropped == 0


def test_consecutive_beats_increment_nonce(
    bound_uds_listener: Tuple[socket.socket, Path],
) -> None:
    listener, path = bound_uds_listener
    listener.setblocking(False)
    with Varta.connect(path) as agent:
        for _ in range(5):
            outcome = agent.beat(Status.OK)
            assert outcome.is_sent
        nonces = []
        while True:
            try:
                data, _ = listener.recvfrom(64)
            except BlockingIOError:
                break
            nonces.append(decode(data).nonce)
        assert nonces == [1, 2, 3, 4, 5]


def test_connect_to_nonexistent_path_raises(tmp_uds_path: Path) -> None:
    # tmp_uds_path is a clean path with no listener — connect must fail.
    with pytest.raises(OSError):
        Varta.connect(tmp_uds_path)


def test_uds_failed_reconnect_preserves_socket(
    bound_uds_listener: Tuple[socket.socket, Path],
) -> None:
    listener, path = bound_uds_listener
    transport = UdsTransport(path)
    old_sock = transport._sock
    listener.close()
    path.unlink()

    try:
        with pytest.raises(OSError):
            transport.reconnect()
        assert transport._sock is old_sock
        assert old_sock is not None
        assert old_sock.fileno() >= 0
    finally:
        transport.close()


def test_udp_failed_reconnect_preserves_socket() -> None:
    transport = UdpTransport(("127.0.0.1", 9))
    old_sock = transport._sock
    transport._addr = ("[", 9)

    try:
        with pytest.raises(OSError):
            transport.reconnect()
        assert transport._sock is old_sock
        assert old_sock is not None
        assert old_sock.fileno() >= 0
    finally:
        transport.close()


def test_secure_udp_failed_reconnect_preserves_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = SecureUdpTransport(("127.0.0.1", 9), key=bytes(32))
    transport._set_iv_counter_for_test(17)
    old_sock = transport._sock
    old_session = (
        transport._session_salt,
        transport._iv_prefix,
        transport._iv_prefix_index,
        transport._iv_counter,
    )

    def fail_entropy(_: int) -> bytes:
        raise OSError(errno.EIO, "simulated entropy failure")

    monkeypatch.setattr("varta._transport.os.urandom", fail_entropy)
    try:
        with pytest.raises(OSError):
            transport.reconnect()
        assert transport._sock is old_sock
        assert old_sock is not None
        assert old_sock.fileno() >= 0
        assert (
            transport._session_salt,
            transport._iv_prefix,
            transport._iv_prefix_index,
            transport._iv_counter,
        ) == old_session
    finally:
        transport.close()


# ---------------------------------------------------------------------------
# Fork-recovery and clock-regression counters.
# ---------------------------------------------------------------------------


def test_same_pid_does_not_trigger_fork_recovery(
    bound_uds_listener: Tuple[socket.socket, Path],
) -> None:
    _, path = bound_uds_listener
    with Varta.connect(path) as agent:
        for _ in range(20):
            agent.beat(Status.OK)
        assert agent.fork_recoveries() == 0


def test_spoofed_fork_triggers_reconnect_and_increments_counter(
    bound_uds_listener: Tuple[socket.socket, Path],
) -> None:
    _, path = bound_uds_listener
    with Varta.connect(path) as agent:
        agent.beat(Status.OK)
        agent.beat(Status.OK)
        assert agent.fork_recoveries() == 0
        agent._set_connect_pid_for_test(os.getpid() ^ 0x1)
        outcome = agent.beat(Status.OK)
        assert outcome.is_sent
        assert agent.fork_recoveries() == 1
        # Nonce resets to 0 then increments to 1.
        assert agent._nonce == 1
        assert agent._connect_pid == os.getpid()


def test_clock_regression_counter_increments(
    bound_uds_listener: Tuple[socket.socket, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, path = bound_uds_listener
    import varta.client as client_mod

    with Varta.connect(path) as agent:
        agent.beat(Status.OK)
        # Jam the high-water mark past any plausible elapsed value.
        agent._last_timestamp = 2**60
        baseline = agent._last_timestamp
        agent.beat(Status.OK)
        assert agent.clock_regressions() == 1
        # Wire timestamp clamped via max().
        assert agent._last_timestamp == baseline
        agent.beat(Status.OK)
        assert agent.clock_regressions() == 2
    _ = client_mod  # keep import used


def test_nonce_wraps_to_zero_at_terminal(
    bound_uds_listener: Tuple[socket.socket, Path],
) -> None:
    _, path = bound_uds_listener
    with Varta.connect(path) as agent:
        agent._set_nonce_for_test(NONCE_TERMINAL - 2)
        agent.beat(Status.OK)
        assert agent._nonce == NONCE_TERMINAL - 1
        # Next beat must wrap (terminal nonce is reserved for Critical panics).
        agent.beat(Status.OK)
        assert agent._nonce == 0


# ---------------------------------------------------------------------------
# Auto-reconnect.
# ---------------------------------------------------------------------------


class _CountingTransport(BeatTransport):
    """Deterministically drops the first N sends, then sends successfully."""

    def __init__(self, drop_count: int) -> None:
        self._remaining_drops = drop_count
        self.send_calls = 0
        self.reconnect_calls = 0

    def send(self, buf: bytes) -> int:
        self.send_calls += 1
        if self._remaining_drops > 0:
            self._remaining_drops -= 1
            raise BlockingIOError()
        return len(buf)

    def reconnect(self) -> None:
        self.reconnect_calls += 1


def test_auto_reconnect_after_threshold() -> None:
    # drop_count=2 → first two sends drop; threshold=2 → on beat 2 we
    # reconnect and the retry (3rd send) succeeds.
    transport = _CountingTransport(drop_count=2)
    agent = Varta(transport)
    agent.set_reconnect_after(2)
    out1 = agent.beat(Status.OK)
    assert out1.is_dropped
    assert transport.reconnect_calls == 0  # threshold not yet reached
    out2 = agent.beat(Status.OK)
    assert transport.reconnect_calls == 1
    assert out2.is_sent
    assert transport.send_calls == 3  # 2 drops + 1 retry send


def test_set_reconnect_after_zero_disables() -> None:
    transport = _CountingTransport(drop_count=10)
    agent = Varta(transport)
    agent.set_reconnect_after(0)
    for _ in range(5):
        agent.beat(Status.OK)
    assert transport.reconnect_calls == 0


class _DropAndFailReconnect(BeatTransport):
    """Always drops on send; reconnect always fails."""

    def __init__(self) -> None:
        self.reconnect_calls = 0

    def send(self, buf: bytes) -> int:
        raise BlockingIOError()

    def reconnect(self) -> None:
        self.reconnect_calls += 1
        raise OSError(errno.ECONNREFUSED, "refused")


def test_failed_reconnect_preserves_consecutive_dropped_for_immediate_retry() -> None:
    # A failed auto-reconnect must NOT disarm the counter: once the
    # threshold is crossed, every subsequent Dropped beat retries the
    # reconnect immediately rather than re-arming a full window. Mirrors
    # the Rust regression of the same name and the frozen cross-client
    # contract (reset only on a successful reconnect).
    transport = _DropAndFailReconnect()
    agent = Varta(transport)
    agent.set_reconnect_after(2)

    # First drop: 0 -> 1, below threshold, no reconnect attempted.
    assert agent.beat(Status.OK).is_dropped
    assert agent._consecutive_dropped == 1
    assert transport.reconnect_calls == 0

    # Second drop: crosses the threshold; reconnect attempted and FAILS,
    # so the counter must stay saturated at 2.
    assert agent.beat(Status.OK).is_dropped
    assert transport.reconnect_calls == 1
    assert agent._consecutive_dropped == 2

    # Third drop: threshold still crossed → reconnect retried immediately.
    assert agent.beat(Status.OK).is_dropped
    assert transport.reconnect_calls == 2


# ---------------------------------------------------------------------------
# Commit-on-success: a Dropped or Failed send must NOT advance the committed
# nonce/timestamp. Mirrors the Rust regressions in
# crates/varta-client/src/client.rs::tests (dropped_beat_does_not_commit_*,
# failed_beat_does_not_commit_*, reconnect_retry_commits_pending_nonce_only_*,
# dropped_wrap_attempt_does_not_commit_nonce_wrap).
# ---------------------------------------------------------------------------


class _AlwaysDropTransport(BeatTransport):
    """Every send drops (WouldBlock); reconnect is a no-op success."""

    def __init__(self) -> None:
        self.send_calls = 0

    def send(self, buf: bytes) -> int:
        self.send_calls += 1
        raise BlockingIOError()

    def reconnect(self) -> None:
        pass


class _AlwaysFailTransport(BeatTransport):
    """Every send fails with a non-droppable errno (-> BeatOutcome.failed)."""

    def send(self, buf: bytes) -> int:
        raise OSError(errno.EACCES, "EACCES")

    def reconnect(self) -> None:
        pass


def test_dropped_beat_does_not_commit_nonce_or_timestamp() -> None:
    agent = Varta(_AlwaysDropTransport())
    assert agent._nonce == 0
    assert agent._last_timestamp == 0
    out = agent.beat(Status.OK)
    assert out.is_dropped
    # Candidate nonce 1 / candidate timestamp were built and sent, but the
    # send was rejected, so neither is committed.
    assert agent._nonce == 0
    assert agent._last_timestamp == 0
    # The next beat reuses the same candidate (still 1), never 2.
    assert agent.beat(Status.OK).is_dropped
    assert agent._nonce == 0


def test_failed_beat_does_not_commit_nonce_or_timestamp() -> None:
    agent = Varta(_AlwaysFailTransport())
    out = agent.beat(Status.OK)
    assert out.is_failed
    assert agent._nonce == 0
    assert agent._last_timestamp == 0


def test_first_successful_beat_after_drop_reuses_nonce_one() -> None:
    # Drop once (reconnect disabled), then send. The accepted frame must carry
    # nonce 1 — the dropped attempt did not burn it.
    transport = _CountingTransport(drop_count=1)
    agent = Varta(transport)
    assert agent.beat(Status.OK).is_dropped
    assert agent._nonce == 0
    assert agent.beat(Status.OK).is_sent
    assert agent._nonce == 1


def test_reconnect_retry_commits_nonce_only_on_successful_retry() -> None:
    # drop_count=2 + threshold=2: beat 2 reconnects and the retry succeeds, so
    # the committed nonce is 1 (the un-burned candidate), not 2.
    transport = _CountingTransport(drop_count=2)
    agent = Varta(transport)
    agent.set_reconnect_after(2)
    assert agent.beat(Status.OK).is_dropped
    assert agent._nonce == 0
    assert agent.beat(Status.OK).is_sent
    assert agent._nonce == 1


def test_failed_reconnect_does_not_commit_nonce() -> None:
    transport = _DropAndFailReconnect()
    agent = Varta(transport)
    agent.set_reconnect_after(1)
    # Drop crosses threshold; reconnect raises -> dropped returned, no retry,
    # so the nonce stays uncommitted.
    assert agent.beat(Status.OK).is_dropped
    assert agent._nonce == 0


def test_dropped_wrap_attempt_does_not_commit_nonce_wrap() -> None:
    agent = Varta(_AlwaysDropTransport())
    agent._set_nonce_for_test(NONCE_TERMINAL - 1)
    # The candidate wraps to 0, but the send drops, so the wrap is not
    # committed and the warning does not fire for an un-sent frame.
    assert agent.beat(Status.OK).is_dropped
    assert agent._nonce == NONCE_TERMINAL - 1


# ---------------------------------------------------------------------------
# BeatError + BeatOutcome plumbing.
# ---------------------------------------------------------------------------


def test_beat_error_to_oserror_roundtrip() -> None:
    err = BeatError(errno=errno.EPERM, kind="EPERM")
    rt = err.to_oserror()
    assert isinstance(rt, OSError)
    assert rt.errno == errno.EPERM


def test_beat_outcome_constructors_distinct() -> None:
    sent = BeatOutcome.sent()
    dropped = BeatOutcome.dropped(DropReason.PEER_GONE)
    failed = BeatOutcome.failed(BeatError(errno=99, kind="x"))
    assert sent.is_sent and not sent.is_dropped and not sent.is_failed
    assert dropped.is_dropped and dropped.reason is DropReason.PEER_GONE
    assert failed.is_failed and failed.error is not None
