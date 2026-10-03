"""Capture import pipeline shared by HTTP layer and scripts."""

from __future__ import annotations

import base64
import os
import uuid

from .pcap_reader import parse_pcap
from .reassembler import (
    LimitExceeded,
    read_segments,
    reassemble,
)
from .storage import CaptureStore, build_document

MAX_UPLOAD = 50 * 1024 * 1024
MAX_GENERATIONS = 200
MAX_SPAN = 8 * 1024 * 1024


class UploadTooLarge(Exception):
    pass


class ImportError400(Exception):
    pass


def import_pcap(data: bytes, store: CaptureStore) -> str:
    """Parse, reassemble and atomically persist one capture.

    Raises on any error after cleaning temp data; returns capture id.
    """
    if len(data) > MAX_UPLOAD:
        raise UploadTooLarge(
            f"upload {len(data)} bytes exceeds 50 MiB limit"
        )
    try:
        tcp_packets, skipped = parse_pcap(data)
        generations, missing_syn = reassemble(
            tcp_packets,
            max_generations=MAX_GENERATIONS,
            max_span=MAX_SPAN,
        )
    except LimitExceeded as exc:
        raise ImportError400(str(exc)) from exc

    capture_id = uuid.uuid4().hex
    payload = build_document(
        capture_id=capture_id,
        generations=generations,
        skipped=skipped,
        missing_syn=missing_syn,
        packet_count=_count_records(data),
    )
    tmp_path = store.save_temp(capture_id, payload)
    try:
        store.commit(tmp_path, capture_id)
    except BaseException:
        store.cleanup(tmp_path)
        raise
    return capture_id


def _count_records(data: bytes) -> int:
    # packet count: total records including skipped; parse_pcap counted only
    # TCP packets, so derive from the raw iterator cheaply.
    from .pcap_reader import _iter_raw_records

    return sum(1 for _ in _iter_raw_records(data))


def public_view(payload: dict) -> dict:
    """Strip persisted segment payloads from the query response."""
    view = dict(payload)
    view["connections"] = _strip_segments(payload["connections"])
    return view


def _strip_segments(connections: list[dict]) -> list[dict]:
    result = []
    for conn in connections:
        conn_view = {k: v for k, v in conn.items()}
        for direction_key in ("initiator_to_responder",
                              "responder_to_initiator"):
            direction = dict(conn_view[direction_key])
            direction.pop("segments", None)
            conn_view[direction_key] = direction
        result.append(conn_view)
    return result


def get_direction(payload: dict, generation_id: int, direction: str):
    for conn in payload["connections"]:
        if conn["generation_id"] == generation_id:
            if direction == "c2s":
                return conn["initiator_to_responder"]
            if direction == "s2c":
                return conn["responder_to_initiator"]
            return None
    return None


def download_bytes(
    payload: dict,
    generation_id: int,
    direction: str,
    offset: int,
    length: int,
) -> bytes | None:
    direction_state = get_direction(payload, generation_id, direction)
    if direction_state is None:
        raise KeyError("generation or direction not found")
    segments = [
        (
            seg["start"],
            seg["end"],
            base64.b64decode(seg["data"]),
        )
        for seg in direction_state.get("segments", [])
    ]
    return read_segments(segments, offset, length)


def default_store() -> CaptureStore:
    directory = os.environ.get("PCAP_STORE_DIR", "data/captures")
    return CaptureStore(directory)
