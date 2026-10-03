from __future__ import annotations

import struct
import sys
from pathlib import Path

import dpkt
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from app.pcap_reader import PcapError, read_pcap  # noqa: E402
from app.reassembly import LimitError, reassemble  # noqa: E402
from make_sample_pcaps import (  # noqa: E402
    ACK,
    FIN,
    RST,
    SYN,
    build_demo,
    build_nano_be,
    build_truncated,
    ether,
    ip_packet,
    packet_record,
    global_header,
    tcp_packet,
)


C, S = "10.0.0.1", "10.0.0.2"
CP, SP = 40000, 80


def _result(raw: bytes):
    packets, stats = read_pcap(raw)
    return reassemble(packets, stats), stats


def test_demo_generations_and_skips():
    result, stats = _result(build_demo())
    assert stats.total_packets == 16
    assert result.orphan_packets == 1
    assert stats.skipped["ipv6"] == 1
    assert stats.skipped["non_tcp_ipv4"] == 1
    assert stats.skipped["fragmented_ipv4"] == 1
    assert len(result.generations) == 2
    assert result.generations[0].close_reason == "fin"
    assert result.generations[1].close_reason == "rst"


def test_reassembly_content_gap_conflict():
    result, _ = _result(build_demo())
    c2s = result.generations[0].c2s
    buf = c2s.payload()
    assert buf[0:5] == b"HELLO"
    assert buf[5:9] == b"zzzz"       # 缺口由后到包填充
    assert buf[10:18] == b"WORLD!!!"  # 冲突字节保留文件中先到内容
    assert c2s.span_end == 18         # 18 字节数据，FIN 位置等于 exclusive end
    assert c2s.to_dict()["gaps"] == [[9, 10]]
    assert c2s.to_dict()["conflicts"] == [
        {"start": 3, "end": 5, "packets": [5, 7]}
    ]
    assert c2s.retransmissions == 1
    assert result.generations[0].s2c.payload() == b"OK"


def test_nanosecond_big_endian_equivalent():
    result, stats = _result(build_nano_be())
    assert stats.total_packets == 16
    assert len(result.generations) == 2


def test_truncated_raises():
    with pytest.raises(PcapError):
        read_pcap(build_truncated())
    with pytest.raises(PcapError):
        read_pcap(b"\x00\x00\x00")
    with pytest.raises(PcapError):
        read_pcap(b"\x00" * 24)


def _raw(frames, endian="<", nano=False):
    out = global_header(endian, nano)
    for ts, frame in frames:
        out += packet_record(endian, nano, ts, frame)
    return out


def _frame(seq, ackn, flags, data=b"", src=C, dst=S, sp=CP, dp=SP):
    seg = tcp_packet(sp, dp, seq, ackn, flags, data)
    return ether(ip_packet(src, dst, seg))


def test_wrap_around():
    isn = 0xFFFFFFFA
    frames = [
        (1.0, _frame(isn, 0, SYN)),
        (1.001, _frame(0x1234, isn + 1, SYN | ACK, src=S, dst=C, sp=SP, dp=CP)),
        # 4 字节跨越回绕点 + 随后 2 字节
        (1.002, _frame(isn + 1, 0x1235, ACK, b"ABCD", )),
        (1.003, _frame((isn + 5) & 0xFFFFFFFF, 0x1235, ACK, b"EF")),
        (1.004, _frame((isn + 7) & 0xFFFFFFFF, 0x1235, FIN | ACK)),
        (1.005, _frame(0x1235, (isn + 8) & 0xFFFFFFFF, FIN | ACK,
                       src=S, dst=C, sp=SP, dp=CP)),
    ]
    result, _ = _result(_raw(frames))
    assert len(result.generations) == 1
    c2s = result.generations[0].c2s
    assert c2s.payload() == b"ABCDEF"
    assert c2s.span_end == 6
    assert c2s.to_dict()["gaps"] == []


def test_same_seq_syn_is_retransmission_new_seq_is_generation():
    frames = [
        (1.0, _frame(1000, 0, SYN)),
        (1.001, _frame(1000, 0, SYN)),          # 重传
        (1.002, _frame(5000, 1001, SYN | ACK, src=S, dst=C, sp=SP, dp=CP)),
        (1.003, _frame(1001, 5001, ACK, b"aa")),
        (1.004, _frame(1001, 5001, RST)),
        (1.005, _frame(2000, 0, SYN)),          # 关闭后的 SYN => 新代
    ]
    result, _ = _result(_raw(frames))
    assert len(result.generations) == 2
    assert result.generations[0].c2s.payload() == b"aa"
    assert result.generations[0].close_reason == "rst"
    assert result.generations[1].c2s.isn == 2000


def test_missing_syn_is_orphan():
    frames = [
        (1.0, _frame(1234, 99, ACK, b"data")),  # 无 SYN
        (1.001, _frame(1234, 99, RST)),
    ]
    result, stats = _result(_raw(frames))
    assert result.generations == []
    assert result.orphan_packets == 2
    assert stats.tcp_packets == 2


def test_span_limit_rejected():
    from app.reassembly import DirectionStream

    stream = DirectionStream("c2s")
    stream.init_isn(1000, 1.0)
    with pytest.raises(LimitError):
        stream.add_data(1001, b"x" * (8 * 1024 * 1024 + 1), 1)
