from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from fastapi.testclient import TestClient  # noqa: E402

from app import main as main_module  # noqa: E402
from app.repository import CaptureStore  # noqa: E402
from make_sample_pcaps import build_demo, build_truncated  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main_module, "store", CaptureStore(tmp_path / "db"))
    with TestClient(main_module.app) as c:
        yield c


def test_upload_query_and_download(client):
    resp = client.post(
        "/captures",
        files={"file": ("demo.pcap", io.BytesIO(build_demo()), "application/vnd.tcpdump.pcap")},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    cid = body["capture_id"]
    assert body["generation_count"] == 2
    assert body["skipped"]["fragmented_ipv4"] == 1

    listing = client.get("/captures").json()
    assert listing["captures"][0]["capture_id"] == cid

    gen = client.get(f"/captures/{cid}/generations/0").json()
    assert gen["close_reason"] == "fin"
    assert gen["directions"]["c2s"]["gaps"] == [[9, 10]]

    # 已连续区间下载
    r = client.get(
        f"/captures/{cid}/generations/0/bytes",
        params={"direction": "c2s", "offset": 0, "length": 9},
    )
    assert r.status_code == 200
    assert r.content == b"HELLOzzzz"

    # 跨缺口 => 409
    r = client.get(
        f"/captures/{cid}/generations/0/bytes",
        params={"direction": "c2s", "offset": 0, "length": 12},
    )
    assert r.status_code == 409
    assert r.json()["detail"]["gaps"] == [[9, 10]]

    # s2c
    r = client.get(
        f"/captures/{cid}/generations/0/bytes",
        params={"direction": "s2c", "offset": 0, "length": 2},
    )
    assert r.status_code == 200
    assert r.content == b"OK"


def test_truncated_is_rejected_without_partial_results(client):
    resp = client.post(
        "/captures",
        files={"file": ("t.pcap", io.BytesIO(build_truncated()), "application/octet-stream")},
    )
    assert resp.status_code == 422
    assert client.get("/captures").json()["captures"] == []


def test_404_and_416(client):
    resp = client.post(
        "/captures",
        files={"file": ("d.pcap", io.BytesIO(build_demo()), "application/octet-stream")},
    )
    cid = resp.json()["capture_id"]
    assert client.get("/captures/nope").status_code == 404
    r = client.get(
        f"/captures/{cid}/generations/9/bytes",
        params={"direction": "c2s", "offset": 0, "length": 1},
    )
    assert r.status_code == 404
    r = client.get(
        f"/captures/{cid}/generations/0/bytes",
        params={"direction": "c2s", "offset": 999, "length": 1},
    )
    assert r.status_code == 416


def test_persistence_survives_restart(client, tmp_path):
    resp = client.post(
        "/captures",
        files={"file": ("d.pcap", io.BytesIO(build_demo()), "application/octet-stream")},
    )
    cid = resp.json()["capture_id"]
    # 模拟重启：用同一目录重建 store
    restarted = CaptureStore(tmp_path / "db")
    meta = restarted.get_meta(cid)
    assert meta["generation_count"] == 2
    data, _ = restarted.read_bytes(cid, 0, "c2s", 10, 8)
    assert data == b"WORLD!!!"
