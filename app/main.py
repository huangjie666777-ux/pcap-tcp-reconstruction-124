"""FastAPI application: upload classic PCAP, query reassembled sessions."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, Query, UploadFile
from fastapi.responses import Response

from .pcap_reader import PcapError, TruncatedPcap
from .service import (
    MAX_UPLOAD,
    UploadTooLarge,
    ImportError400,
    default_store,
    download_bytes,
    import_pcap,
    public_view,
)

app = FastAPI(
    title="TCP Session Reassembly API",
    version="1.0.0",
)

store = default_store()


@app.post("/captures")
async def upload_capture(file: UploadFile):
    data = await file.read(MAX_UPLOAD + 1)
    try:
        capture_id = import_pcap(data, store)
    except UploadTooLarge as exc:
        raise HTTPException(status_code=413, detail=str(exc))
    except (PcapError, ImportError400) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"capture_id": capture_id, "size": len(data)}


@app.get("/captures")
def list_captures():
    return {"captures": store.list_captures()}


@app.get("/captures/{capture_id}")
def get_capture(capture_id: str):
    doc = store.load(capture_id)
    if doc is None:
        raise HTTPException(status_code=404, detail="capture not found")
    return public_view(doc.payload)


@app.get("/captures/{capture_id}/generations/{generation_id}/bytes")
def get_bytes(
    capture_id: str,
    generation_id: int,
    direction: str = Query(..., pattern="^(c2s|s2c)$"),
    offset: int = Query(..., ge=0),
    length: int = Query(..., gt=0, le=8 * 1024 * 1024),
):
    doc = store.load(capture_id)
    if doc is None:
        raise HTTPException(status_code=404, detail="capture not found")
    try:
        content = download_bytes(
            doc.payload, generation_id, direction, offset, length
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    if content is None:
        raise HTTPException(
            status_code=409,
            detail="requested range spans a gap; not byte-for-byte available",
        )
    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={
            "Content-Length": str(len(content)),
            "X-Reassembled": "true",
        },
    )
