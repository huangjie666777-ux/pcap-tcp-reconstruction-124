"""HTTP 接口：上传 PCAP、查询重组结果、按区间下载字节。"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import Response

from .pcap_reader import PcapError, read_pcap
from .reassembly import LimitError, reassemble
from .repository import CaptureStore, NotFoundError

MAX_UPLOAD = 50 * 1024 * 1024
DATA_DIR = Path(os.environ.get("PCAP_DB_DIR", Path.cwd() / "data"))

app = FastAPI(title="TCP 会话还原服务", version="1.0.0")
store = CaptureStore(DATA_DIR)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/captures")
async def upload_capture(file: UploadFile = File(...)) -> dict:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_UPLOAD:
            raise HTTPException(status_code=413, detail="上传文件超过 50MiB 限制")
        chunks.append(chunk)
    if total == 0:
        raise HTTPException(status_code=400, detail="上传内容为空")
    data = b"".join(chunks)

    try:
        packets, stats = read_pcap(data)
        result = reassemble(packets, stats)
        capture_id = store.save(result, file.filename or "upload.pcap", total)
    except PcapError as exc:
        raise HTTPException(status_code=422, detail=f"PCAP 解析失败：{exc}") from exc
    except LimitError as exc:
        raise HTTPException(status_code=422, detail=f"重组限制：{exc}") from exc

    return {
        "capture_id": capture_id,
        "source_filename": file.filename,
        "size_bytes": total,
        "total_packets": result.total_packets,
        "tcp_packets": result.tcp_packets,
        "orphan_packets": result.orphan_packets,
        "skipped": result.skipped,
        "generation_count": len(result.generations),
    }


@app.get("/captures")
def list_captures() -> dict:
    return store.list_captures()


@app.get("/captures/{capture_id}")
def get_capture(capture_id: str) -> dict:
    try:
        return store.get_meta(capture_id)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="抓包记录不存在")


@app.get("/captures/{capture_id}/generations/{generation}")
def get_generation(capture_id: str, generation: int) -> dict:
    try:
        return store.get_generation(capture_id, generation)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="抓包记录或代号不存在")


@app.get("/captures/{capture_id}/generations/{generation}/bytes")
def download_bytes(
    capture_id: str,
    generation: int,
    direction: str = Query(..., pattern="^(c2s|s2c)$"),
    offset: int = Query(..., ge=0),
    length: int = Query(..., gt=0, le=8 * 1024 * 1024),
) -> Response:
    try:
        gaps = store.gaps_in_range(capture_id, generation, direction, offset, length)
        if gaps:
            raise HTTPException(
                status_code=409,
                detail={"message": "请求区间跨越缺口", "gaps": gaps},
            )
        data, span = store.read_bytes(
            capture_id, generation, direction, offset, length
        )
    except NotFoundError:
        raise HTTPException(status_code=404, detail="抓包记录、代号或方向不存在")
    if not data:
        raise HTTPException(
            status_code=416,
            detail={"message": "请求范围超出已知跨度", "span": span},
        )
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Length": str(len(data))},
    )
