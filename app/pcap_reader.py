"""经典 PCAP（libpcap）读取与链路层解析。

支持大小端、微秒/纳秒魔数；仅处理 Ethernet 内未分片 IPv4/TCP，
其余协议按类别计数跳过；容器或报文截断抛出 :class:`PcapError`。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

import dpkt


class PcapError(ValueError):
    """PCAP 容器损坏或报文截断。"""


_MAGICS = {
    b"\xa1\xb2\xc3\xd4": (">", False),  # 大端、微秒
    b"\xd4\xc3\xb2\xa1": ("<", False),  # 小端、微秒
    b"\xa1\xb2\x3c\x4d": (">", True),   # 大端、纳秒
    b"\x4d\x3c\xb2\xa1": ("<", True),   # 小端、纳秒
}

ETH_TYPE_IP4 = 0x0800
ETH_TYPE_IP6 = 0x86DD
VLAN_TYPES = {0x8100, 0x88A8, 0x9100}

IP_FLAG_MF = 0x2000
IP_OFFMASK = 0x1FFF

SKIP_NON_ETHERNET = "non_ethernet_linktype"
SKIP_NON_IP = "non_ip_protocol"
SKIP_IPV6 = "ipv6"
SKIP_FRAGMENTED = "fragmented_ipv4"
SKIP_NON_TCP = "non_tcp_ipv4"


@dataclass(frozen=True)
class TcpPacket:
    packet_no: int
    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int
    payload: bytes


@dataclass
class ReadStats:
    total_packets: int = 0
    tcp_packets: int = 0
    skipped: dict[str, int] = field(default_factory=dict)

    def skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1


def _inet_ntoa(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


def _parse_eth(frame: bytes, packet_no: int, ts: float, stats: ReadStats):
    if len(frame) < 14:
        raise PcapError("Ethernet 帧截断")
    eth_type = struct.unpack(">H", frame[12:14])[0]
    l3 = frame[14:]
    while eth_type in VLAN_TYPES:
        if len(l3) < 4:
            raise PcapError("802.1Q 标签截断")
        eth_type = struct.unpack(">H", l3[2:4])[0]
        l3 = l3[4:]
    if eth_type == ETH_TYPE_IP6:
        stats.skip(SKIP_IPV6)
        return None
    if eth_type != ETH_TYPE_IP4:
        stats.skip(SKIP_NON_IP)
        return None

    if len(l3) < 20:
        raise PcapError("IPv4 报文截断")
    if l3[0] >> 4 != 4:
        raise PcapError("IPv4 版本字段错误")
    ihl = (l3[0] & 0x0F) * 4
    if ihl < 20 or len(l3) < ihl:
        raise PcapError("IPv4 首部截断")
    total_len = struct.unpack(">H", l3[2:4])[0]
    if total_len < ihl or total_len > len(l3):
        raise PcapError("IPv4 报文截断或长度非法")
    frag_field = struct.unpack(">H", l3[6:8])[0]
    if frag_field & (IP_FLAG_MF | IP_OFFMASK):
        stats.skip(SKIP_FRAGMENTED)
        return None
    if l3[9] != dpkt.ip.IP_PROTO_TCP:
        stats.skip(SKIP_NON_TCP)
        return None

    try:
        ip = dpkt.ip.IP(l3[:total_len])
        tcp = ip.data
    except dpkt.DpktError as exc:
        raise PcapError(f"IPv4/TCP 解析失败: {exc}") from exc
    if not isinstance(tcp, dpkt.tcp.TCP):
        stats.skip(SKIP_NON_TCP)
        return None
    data_off = tcp.off * 4
    ip_payload_len = total_len - ihl
    if data_off < 20 or data_off > ip_payload_len:
        raise PcapError("TCP 首部截断")
    return TcpPacket(
        packet_no=packet_no,
        ts=ts,
        src_ip=_inet_ntoa(bytes(ip.src)),
        dst_ip=_inet_ntoa(bytes(ip.dst)),
        src_port=tcp.sport,
        dst_port=tcp.dport,
        seq=tcp.seq & 0xFFFFFFFF,
        ack=tcp.ack & 0xFFFFFFFF,
        flags=tcp.flags,
        payload=bytes(l3[ihl + data_off : total_len]),
    )


def read_pcap(data: bytes) -> tuple[list[TcpPacket], ReadStats]:
    """解析整份经典 PCAP；任何截断/损坏均抛 PcapError。"""
    if len(data) < 24:
        raise PcapError("PCAP 全局头截断")
    magic = data[:4]
    if magic not in _MAGICS:
        raise PcapError("未知 PCAP 魔数（非经典 PCAP）")
    endian, nano = _MAGICS[magic]
    major, minor, _tz, _sigfigs, snaplen, linktype = struct.unpack(
        endian + "HHIIII", data[4:24]
    )
    if (major, minor) != (2, 4):
        raise PcapError(f"不支持的 PCAP 版本 {major}.{minor}")

    stats = ReadStats()
    packets: list[TcpPacket] = []
    pos = 24
    total = len(data)
    while pos < total:
        if total - pos < 16:
            raise PcapError("数据包头截断")
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(
            endian + "IIII", data[pos : pos + 16]
        )
        pos += 16
        if snaplen and incl_len > snaplen:
            raise PcapError("捕获长度超过 snaplen")
        if incl_len > total - pos:
            raise PcapError("报文数据截断")
        if orig_len > incl_len:
            raise PcapError("报文在捕获时被截断（snaplen 切包）")
        frame = data[pos : pos + incl_len]
        pos += incl_len
        stats.total_packets += 1

        if linktype != dpkt.pcap.DLT_EN10MB:
            stats.skip(SKIP_NON_ETHERNET)
            continue
        ts = ts_sec + ts_frac / (1_000_000_000 if nano else 1_000_000)
        parsed = _parse_eth(frame, stats.total_packets, ts, stats)
        if parsed is not None:
            packets.append(parsed)
            stats.tcp_packets += 1
    return packets, stats
