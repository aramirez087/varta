"""Varta — health protocol client for distributed local agents.

Public surface mirrors the Rust crate ``varta-client``:

- :class:`Varta`              — agent handle (see :meth:`Varta.connect`)
- :class:`Status`             — beat status (Ok / Degraded / Critical)
- :class:`BeatOutcome`        — result of a single beat
- :class:`DropReason`         — four-way drop taxonomy
- :class:`BeatError`          — error payload for ``failed`` outcomes
- :class:`Frame`              — decoded view of a wire frame
- :class:`DecodeError`        — wire-validation failure
- :data:`NONCE_TERMINAL`      — reserved nonce paired with Critical panics
- :func:`classify_send_error` — re-export for custom-transport authors
- :mod:`varta.panic`          — install_excepthook_* family

The normative wire spec is at ``book/src/spec/vlp.md`` in the Varta
repository.
"""

from __future__ import annotations

from . import panic as panic
from ._vlp import (
    NONCE_TERMINAL as NONCE_TERMINAL,
    DecodeError as DecodeError,
    Frame as Frame,
    Status as Status,
)
from .client import (
    BeatError as BeatError,
    BeatOutcome as BeatOutcome,
    DropReason as DropReason,
    Varta as Varta,
    classify_send_error as classify_send_error,
)

__version__ = "0.2.0"

__all__ = [
    "__version__",
    "Varta",
    "Status",
    "Frame",
    "DecodeError",
    "BeatOutcome",
    "DropReason",
    "BeatError",
    "NONCE_TERMINAL",
    "classify_send_error",
    "panic",
]
