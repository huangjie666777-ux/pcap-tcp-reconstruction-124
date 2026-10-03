from __future__ import annotations

import os
import struct

import dpkt
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.pcap_reader import TruncatedPcap, parse_pcap
from app.reassembler import (LimitExceeded, SEQ_SPACE, reassemble)
from scripts.generate_sample import (
    MAGIC_NS_LE, arp_frame, make_frame, udp_frame, write_pcap,
)

TH_SYN = dpkt.tcp.TH_SYN
TH_ACK = dpkt.tcp.TH_ACK
TH_FIN = dpkt.tcp.TH_FIN
TH_RST = dpkt.tcp.TH_RST
TH_PUSH = dpkt.tcp.TH_PUSH

C_IP = bytes([10, 0, 0, 1])
S_IP = bytes([10, 0, 0, 2])


def frame(seq, ack, flags, payload=b"", sport=1111, dport=80,
          src=C_IP, dst=S_IP):
    return make_frame(src, dst, sport, dport, seq, ack, flags, payload)


def handshake(c=1000, s=5000):
    return [
        frame(c, 0, TH_SYN),
        frame(s, c + 1, TH_SYN | TH_ACK, sport=80, dport=1111,
              src=S_IP, dst=C_IP),
        frame(c + 1, s + 1, TH_ACK),
    ]


def build(records, magic=MAGIC_NS_LE):
    import io
    import tempfile

    path = tempfile.mktemp(suffix=".pcap")
    # magic controls endianness/resolution via generator default; handle BE ns
    write_pcap(path, records)
    if magic != MAGIC_NS_LE:
        with open(path, "rb") as handle:
            data = bytearray(handle.read())
        if magic == 0xA1B2A1B2:
            # rewrite magic and integer fields big-endian microsecond
            fields = struct.unpack_from("<IHHIIII", data, 0)
            struct.pack_into(">IHHIIII", data, 0,
                             magic, *fields[1:])
            off = 24
            while off < len(data):
                ts_sec, ts_ns, incl, orig = struct.unpack_from(
                    "<IIII", data, off)
                struct.pack_into(">IIII", data, off,
                                 ts_sec, ts_ns // 1000, incl, orig)
                off += 16 + incl
        with open(path, "wb") as handle:
            handle.write(data)
    with open(path, "rb") as handle:
        data = handle.read()
    os.unlink(path)
    return data


def test_sample_full_pipeline(tmp_path):
    from scripts.generate_sample import main

    os.environ["SAMPLE_PCAP"] = str(tmp_path / "sample.pcap")
    main()
    with open(os.environ["SAMPLE_PCAP"], "rb") as handle:
        data = handle.read()
    packets, skipped = parse_pcap(data)
    gens, missing = reassemble(packets)
    assert skipped["non_ipv4_ethertype"] == 1  # ARP
    assert skipped["non_tcp"] == 1  # UDP
    assert skipped["fragmented_ipv4"] == 1
    assert missing == 1  # orphan
    assert len(gens) == 2
    g1, g2 = gens
    assert g1.close_reason == "fin"
    assert g2.close_reason == "rst"
    c2s = g1.c2s
    # first 10 bytes, gap-fill 10..14, later 15..19, gap 20..30
    assert c2s.covered_intervals() == [[0, 20]]
    assert c2s.gaps() == [[20, 30]]
    # conflict recorded on offsets 15..19, first-seen content PQRST
    assert c2s.conflicts == [
        {"start": 15, "end": 20, "packets": [7, 8]}
    ]
    assert c2s.read(0, 20) == b"0123456789KLMNOPQRST"
    assert c2s.read(0, 21) is None
    assert g1.s2c.read(0, 5) == b"HELLO"
    assert g1.s2c.gaps() == []


def test_truncated_container_and_packet_rejected(tmp_path):
    data = build(handshake())
    with pytest.raises(TruncatedPcap):
        parse_pcap(data[:-5])
    with pytest.raises(TruncatedPcap):
        parse_pcap(data[:30])


def test_big_endian_microsecond_pcap():
    packets, skipped = parse_pcap(build(handshake(), magic=0xA1B2A1B2))
    assert len(packets) == 3
    # microsecond resolution converted to nanoseconds, order preserved
    assert packets[0].ts_frac == 1000


def test_same_syn_retransmit_new_syn_new_generation():
    records = handshake()
    # retransmit opening SYN (same seq) -> same generation
    records.append(frame(1000, 0, TH_SYN))
    records.append(frame(1001, 5001, TH_PUSH | TH_ACK, b"ab"))
    records.append(frame(5001, 1003, TH_ACK, sport=80, dport=1111,
                         src=S_IP, dst=C_IP))
    # close FIN both ways
    records.append(frame(1003, 5001, TH_FIN | TH_ACK))
    records.append(frame(5001, 1004, TH_FIN | TH_ACK, sport=80, dport=1111,
                         src=S_IP, dst=C_IP))
    # new SYN after close -> second generation
    records.append(frame(3000, 0, TH_SYN))
    packets, _ = parse_pcap(build(records))
    gens, missing = reassemble(packets)
    assert missing == 0
    assert [g.gen_id for g in gens] == [1, 2]
    assert gens[0].close_reason == "fin"
    assert gens[0].c2s.read(0, 2) == b"ab"


def test_sequence_wraparound():
    near = SEQ_SPACE - 2
    records = [
        frame(near, 0, TH_SYN),
        frame(4000, near + 1, TH_SYN | TH_ACK, sport=80, dport=1111,
              src=S_IP, dst=C_IP),
        frame(near + 1, 4001, TH_ACK),
        # two bytes at seq -1,0 (wraps), then two at 1,2
        frame(near + 1, 4001, TH_PUSH | TH_ACK, b"\xff\x00"),
        frame(1, 4001, TH_PUSH | TH_ACK, b"cd"),
    ]
    packets, _ = parse_pcap(build(records))
    gens, _ = reassemble(packets)
    assert gens[0].c2s.read(0, 4) == b"\xff\x00cd"
    assert gens[0].c2s.covered_intervals() == [[0, 4]]


def test_generation_limit_and_span_limit(tmp_path):
    records = []
    for i in range(201):
        records.append(frame(10000 + i, 0, TH_SYN, sport=2000 + i))
        records.append(frame(7000 + i, 10001 + i, TH_RST, sport=80,
                            dport=2000 + i, src=S_IP, dst=C_IP))
    packets, _ = parse_pcap(build(records))
    with pytest.raises(LimitExceeded):
        reassemble(packets, max_generations=200)

    # 8 MiB per-direction span limit, checked at insertion level (a single
    # IPv4 datagram cannot legally exceed 64 KiB, so exercise the unit
    # boundary directly).
    from app.reassembler import DirectionState
    d = DirectionState()
    d.syn_seq = 0
    with pytest.raises(LimitExceeded):
        d.insert(
            8 * 1024 * 1024 - 4, 8 * 1024 * 1024 + 1, b"xxxxx", 1,
            max_span=8 * 1024 * 1024,
        )


def test_http_upload_query_download_gap_409(tmp_path, monkeypatch):
    monkeypatch.setenv("PCAP_STORE_DIR", str(tmp_path / "store"))
    # Reload module-level store binding
    import importlib
    import app.service as service
    importlib.reload(service)
    import app.main as main
    importlib.reload(main)
    client = TestClient(main.app)

    path = str(tmp_path / "sample.pcap")
    os.environ["SAMPLE_PCAP"] = path
    from scripts.generate_sample import main as gen
    gen()
    with open(path, "rb") as handle:
        data = handle.read()

    resp = client.post(
        "/captures", files={"file": ("sample.pcap", data, "application/vnd"
                                                              ".tcpdump")})
    assert resp.status_code == 200, resp.text
    capture_id = resp.json()["capture_id"]

    detail = client.get(f"/captures/{capture_id}").json()
    assert len(detail["connections"]) == 2
    dir1 = detail["connections"][0]["initiator_to_responder"]
    assert dir1["known_intervals"] == [[0, 20]]
    assert dir1["gaps"] == [[20, 30]]
    assert "segments" not in dir1

    ok = client.get(
        f"/captures/{capture_id}/generations/1/bytes",
        params={"direction": "c2s", "offset": 0, "length": 20},
    )
    assert ok.status_code == 200
    assert ok.content == b"0123456789KLMNOPQRST"

    bad = client.get(
        f"/captures/{capture_id}/generations/1/bytes",
        params={"direction": "c2s", "offset": 15, "length": 10},
    )
    assert bad.status_code == 409

    # restart: fresh client/store from same directory still sees capture
    importlib.reload(service)
    importlib.reload(main)
    client2 = TestClient(main.app)
    assert client2.get(f"/captures/{capture_id}").status_code == 200


def test_garbage_upload_400_and_413(tmp_path, monkeypatch):
    monkeypatch.setenv("PCAP_STORE_DIR", str(tmp_path / "store"))
    import importlib
    import app.service as service
    importlib.reload(service)
    import app.main as main
    importlib.reload(main)
    client = TestClient(main.app)
    assert client.post(
        "/captures", files={"file": ("x.pcap", b"not-a-pcap",
                                      "application/octet-stream")}
    ).status_code == 400
    assert client.post(
        "/captures", files={"file": ("big.pcap", b"a" * (50 * 1024 * 1024 + 1),
                                      "application/octet-stream")}
    ).status_code == 413
