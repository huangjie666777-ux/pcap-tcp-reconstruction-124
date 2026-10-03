"""抓包结果持久化：临时目录写全 -> 原子发布 -> 索引登记。"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .reassembly import Generation, ReassemblyResult


class NotFoundError(KeyError):
    pass


@contextlib.contextmanager
def _locked_index(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(".lock")
    with open(lock_path, "a+b") as lock_fh:
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
        data = {}
        if path.exists():
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        yield data
        tmp = path.with_suffix(".json.tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        fcntl.flock(lock_fh, fcntl.LOCK_UN)


def _gen_meta(gen: Generation) -> dict:
    return {
        "generation": gen.index,
        "client": {"ip": gen.client_ip, "port": gen.client_port},
        "server": {"ip": gen.server_ip, "port": gen.server_port},
        "close_reason": gen.close_reason,
        "first_ts": gen.first_ts,
        "last_ts": gen.last_ts,
        "directions": {
            "c2s": gen.c2s.to_dict(),
            "s2c": gen.s2c.to_dict(),
        },
    }


class CaptureStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self.captures_dir = self.root / "captures"
        self.index_path = self.root / "index.json"
        self.captures_dir.mkdir(parents=True, exist_ok=True)

    def save(self, result: ReassemblyResult, filename: str, size: int) -> str:
        """成功发布后返回 capture_id；任何失败均清理临时目录。"""
        capture_id = uuid.uuid4().hex
        tmp_dir = Path(
            tempfile.mkdtemp(prefix=f".{capture_id}.", dir=self.captures_dir)
        )
        try:
            for i, gen in enumerate(result.generations):
                gen_dir = tmp_dir / f"gen-{i:04d}"
                gen_dir.mkdir()
                for name, stream in (("c2s", gen.c2s), ("s2c", gen.s2c)):
                    if stream.isn is None:
                        continue
                    payload = stream.payload()
                    self._atomic_write(gen_dir / f"{name}.bin", payload)
            meta = {
                "capture_id": capture_id,
                "source_filename": filename,
                "size_bytes": size,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "total_packets": result.total_packets,
                "tcp_packets": result.tcp_packets,
                "orphan_packets": result.orphan_packets,
                "skipped": result.skipped,
                "generation_count": len(result.generations),
                "generations": [_gen_meta(g) for g in result.generations],
            }
            self._atomic_write(
                tmp_dir / "meta.json",
                json.dumps(meta, ensure_ascii=False, indent=2).encode("utf-8"),
            )

            final_dir = self.captures_dir / capture_id
            os.rename(tmp_dir, final_dir)
            with _locked_index(self.index_path) as index:
                index[capture_id] = {
                    "source_filename": filename,
                    "created_at": meta["created_at"],
                    "generation_count": len(result.generations),
                }
            return capture_id
        except BaseException:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise

    @staticmethod
    def _atomic_write(path: Path, content: bytes) -> None:
        tmp = path.with_name(path.name + ".tmp")
        with open(tmp, "wb") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)

    def _capture_dir(self, capture_id: str) -> Path:
        path = (self.captures_dir / capture_id).resolve()
        if self.captures_dir not in path.parents and path.parent != self.captures_dir:
            raise NotFoundError(capture_id)
        if not path.is_dir():
            raise NotFoundError(capture_id)
        return path

    def _load_meta(self, capture_id: str) -> dict:
        with open(self._capture_dir(capture_id) / "meta.json", "rb") as fh:
            return json.loads(fh.read())

    def list_captures(self) -> dict:
        if self.index_path.exists():
            with open(self.index_path, "r", encoding="utf-8") as fh:
                index = json.load(fh)
        else:
            index = {}
        return {
            "captures": [
                {"capture_id": cid, **entry} for cid, entry in sorted(index.items())
            ]
        }

    def get_meta(self, capture_id: str) -> dict:
        return self._load_meta(capture_id)

    def get_generation(self, capture_id: str, generation: int) -> dict:
        meta = self._load_meta(capture_id)
        for gen in meta["generations"]:
            if gen["generation"] == generation:
                return gen
        raise NotFoundError(f"{capture_id}#{generation}")

    def read_bytes(
        self, capture_id: str, generation: int, direction: str, offset: int, length: int
    ) -> tuple[bytes, bool]:
        """返回 (字节, span_end)；跨缺口由调用方根据 meta 判定。"""
        if direction not in ("c2s", "s2c"):
            raise NotFoundError(direction)
        gen = self.get_generation(capture_id, generation)
        stream = gen["directions"][direction]
        if stream["isn"] is None:
            raise NotFoundError(f"{direction} 无 SYN，方向不存在")
        span = stream["span"]
        end = min(offset + length, span)
        if offset < 0 or offset >= span or end <= offset:
            return b"", span
        bin_path = (
            self._capture_dir(capture_id)
            / f"gen-{generation:04d}"
            / f"{direction}.bin"
        )
        with open(bin_path, "rb") as fh:
            fh.seek(offset)
            return fh.read(end - offset), span

    def gaps_in_range(
        self, capture_id: str, generation: int, direction: str, offset: int, length: int
    ) -> list[list[int]]:
        gen = self.get_generation(capture_id, generation)
        span = gen["directions"][direction]["span"]
        end = min(offset + length, span)
        result = []
        if end <= offset:
            return result
        for gstart, gend in gen["directions"][direction]["gaps"]:
            s = max(gstart, offset)
            e = min(gend, end)
            if s < e:
                result.append([s, e])
        return result
