"""生成自测与演示用经典 PCAP 样例（微秒/纳秒、大小端）。"""

from __future__ import annotations

import struct
import warnings
from pathlib import Path

import dpkt


def global_header(endian: str, nano: bool) -> bytes:
    if endian == ">":
        magic = b"\xa1\xb2\x3c\x4d" if nano else b"\xa1\xb2\xc3\xd4"
    else:
        magic = b"\x4d\x3c\xb2\xa1" if nano else b"\xd4\xc3\xb2\xa1"
    return magic + struct.pack(
        endian + "HHIIII", 2, 4, 0, 0, 65535, dpkt.pcap.DLT_EN10MB
    )


def packet_record(endian: str, nano: bool, ts: float, frame: bytes) -> bytes:
    sec = int(ts)
    frac = int(round((ts - sec) * (1_000_000_000 if nano else 1_000_000)))
    return struct.pack(
        endian + "IIII", sec, frac, len(frame), len(frame)
    ) + frame


def ether(ip_bytes: bytes, eth_type: int = 0x0800) -> bytes:
    return b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + struct.pack(
        ">H", eth_type
    ) + ip_bytes


def ip_packet(
    src: str,
    dst: str,
    tcp_bytes: bytes,
    proto: int = dpkt.ip.IP_PROTO_TCP,
    frag: int = 0,
    payload: bytes | None = None,
) -> bytes:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        ip = dpkt.ip.IP(
            src=b"".join(bytes([int(x)]) for x in src.split(".")),
            dst=b"".join(bytes([int(x)]) for x in dst.split(".")),
            p=proto,
            off=(frag & 0x1FFF) * 8,
            mf=bool(frag & 0x2000),
            ttl=64,
            data=tcp_bytes if payload is None else payload,
        )
    ip.len = len(ip)
    return bytes(ip)


def tcp_packet(
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
) -> bytes:
    tcp = dpkt.tcp.TCP(
        sport=sport,
        dport=dport,
        seq=seq,
        ack=ack,
        off=5,
        flags=flags,
        win=65535,
        data=payload,
    )
    return bytes(tcp)


SYN = dpkt.tcp.TH_SYN
ACK = dpkt.tcp.TH_ACK
FIN = dpkt.tcp.TH_FIN
RST = dpkt.tcp.TH_RST


def build_demo() -> bytes:
    C, S = "10.0.0.1", "10.0.0.2"
    CP, SP = 40000, 80
    cisn, sisn = 1000, 5000
    frames: list[tuple[float, bytes]] = []

    def add(ts, src, dst, sp, dp, seq, ackn, flags, data=b""):
        seg = tcp_packet(sp, dp, seq, ackn, flags, data)
        frames.append((ts, ether(ip_packet(src, dst, seg))))

    # 握手
    add(1.000001, C, S, CP, SP, cisn, 0, SYN)
    add(1.000010, S, C, SP, CP, sisn, cisn + 1, SYN | ACK)
    add(1.000020, C, S, CP, SP, cisn + 1, sisn + 1, ACK)
    PSH = dpkt.tcp.TH_PUSH
    # c2s 数据乱序：offset 10..18 先到（含留待填充的缺口）
    add(1.001, C, S, CP, SP, cisn + 1 + 10, sisn + 1, ACK | PSH, b"WORLD!!!")
    add(1.002, C, S, CP, SP, cisn + 1, sisn + 1, ACK | PSH, b"HELLO")
    # 完全相同段重传 -> 去重
    add(1.003, C, S, CP, SP, cisn + 1 + 10, sisn + 1, ACK | PSH, b"WORLD!!!")
    # 冲突：offset 3..9 内容不同，[3,5) 冲突且保留先到，[5,9) 补缺口留 9..10
    add(1.004, C, S, CP, SP, cisn + 1 + 3, sisn + 1, ACK | PSH, b"zzzzzz")
    # 服务端响应
    add(1.005, S, C, SP, CP, sisn + 1, cisn + 1 + 18, ACK | PSH, b"OK")
    # 关闭：双向 FIN
    add(1.010, C, S, CP, SP, cisn + 1 + 18, sisn + 3, FIN | ACK)
    add(1.011, S, C, SP, CP, sisn + 3, cisn + 1 + 19, FIN | ACK)

    # 第二代：同四元组新 SYN（新序号），RST 关闭
    cisn2 = 9_000_000_000 & 0xFFFFFFFF
    add(2.000, C, S, CP, SP, cisn2, 0, SYN)
    add(2.001, S, C, SP, CP, sisn, cisn2 + 1, RST | ACK)

    # 缺起始 SYN 的孤儿数据
    add(3.000, "10.0.0.3", "10.0.0.4", 5555, 9999, 42, 0, ACK | 0x10, b"orphan")

    # 跳过：IPv6 帧（ethertype 0x86dd，40 字节无扩展 IPv6 头）
    ipv6 = b"\x60\x00\x00\x00\x00\x00\x3b\x40" + bytes(32)
    frames.append((3.001, ether(ipv6, 0x86DD)))
    # 跳过：非 TCP IPv4（UDP）
    udp = (
        struct.pack(">HHHH", 1111, 2222, 8 + 5, 0)
        + b"hello"
    )
    frames.append((3.002, ether(ip_packet(C, S, b"", proto=dpkt.ip.IP_PROTO_UDP, payload=udp))))
    # 跳过：IPv4 分片
    seg = tcp_packet(CP, SP, 1, 1, ACK)
    frames.append((3.003, ether(ip_packet(C, S, seg, frag=0x2000))))

    out = global_header("<", False)
    for ts, frame in frames:
        out += packet_record("<", False, ts, frame)
    return out


def build_truncated() -> bytes:
    good = build_demo()
    return good[: len(good) - 10]


def build_nano_be() -> bytes:
    raw = build_demo()
    out = global_header(">", True)
    pos = 24
    while pos < len(raw):
        sec, usec, incl, orig = struct.unpack("<IIII", raw[pos : pos + 16])
        frame = raw[pos + 16 : pos + 16 + incl]
        out += packet_record(">", True, sec + usec / 1_000_000, frame)
        pos += 16 + incl
    return out


def main() -> None:
    out_dir = Path(__file__).resolve().parent.parent / "samples"
    out_dir.mkdir(exist_ok=True)
    (out_dir / "demo.pcap").write_bytes(build_demo())
    (out_dir / "demo-nano-be.pcap").write_bytes(build_nano_be())
    (out_dir / "truncated.pcap").write_bytes(build_truncated())
    print("wrote samples to", out_dir)


if __name__ == "__main__":
    main()
