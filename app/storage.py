"""Persistent capture store.

Each successful upload is one immutable JSON document written to a temporary
file and atomically renamed, so concurrent uploads never overwrite each other
and a capture becomes queryable only after a successful commit. Temp files are
removed on failure.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
from dataclasses import dataclass

from .reassembler import DirectionState, Generation

DOC_SUFFIX = ".json"
TMP_SUFFIX = ".tmp"


@dataclass
class CaptureDocument:
    capture_id: str
    payload: dict


class CaptureStore:
    def __init__(self, directory: str):
        self.directory = directory
        os.makedirs(directory, exist_ok=True)

    def _path(self, capture_id: str) -> str:
        safe = capture_id.replace(os.sep, "_").replace("/", "_")
        return os.path.join(self.directory, safe + DOC_SUFFIX)

    def save_temp(self, capture_id: str, payload: dict) -> str:
        path = os.path.join(self.directory, capture_id + TMP_SUFFIX)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            raise
        return path

    def commit(self, tmp_path: str, capture_id: str) -> None:
        os.replace(tmp_path, self._path(capture_id))
        self._fsync_dir()

    def _fsync_dir(self) -> None:
        fd = os.open(self.directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def cleanup(self, tmp_path: str) -> None:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass

    def list_captures(self) -> list[str]:
        names = []
        for name in os.listdir(self.directory):
            if name.endswith(DOC_SUFFIX):
                names.append(name[: -len(DOC_SUFFIX)])
        return sorted(names)

    def load(self, capture_id: str) -> CaptureDocument | None:
        path = self._path(capture_id)
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return CaptureDocument(capture_id=capture_id, payload=payload)


def _dir_persist(d: DirectionState) -> dict:
    from .reassembler import _dir_view  # reuse public view

    view = _dir_view(d)
    view["segments"] = [
        {
            "start": seg.start,
            "end": seg.end,
            "data": base64.b64encode(seg.data).decode("ascii"),
            "packet": seg.packet_no,
        }
        for seg in sorted(d.segments, key=lambda s: s.start)
    ]
    return view


def build_document(
    capture_id: str,
    generations: list[Generation],
    skipped: dict[str, int],
    missing_syn: int,
    packet_count: int,
) -> dict:
    """Persist full state including segment payloads (base64)."""
    conns = []
    for gen in generations:
        conns.append({
            "generation_id": gen.gen_id,
            "endpoints": {
                "initiator": {
                    "ip": gen.initiator[0], "port": gen.initiator[1]
                },
                "responder": {
                    "ip": gen.responder[0], "port": gen.responder[1]
                },
            },
            "close_reason": gen.close_reason,
            "first_packet": gen.first_packet,
            "last_packet": gen.last_packet,
            "initiator_to_responder": _dir_persist(gen.c2s),
            "responder_to_initiator": _dir_persist(gen.s2c),
        })
    return {
        "capture_id": capture_id,
        "packet_count": packet_count,
        "skipped": skipped,
        "missing_syn_packets": missing_syn,
        "connections": conns,
    }
