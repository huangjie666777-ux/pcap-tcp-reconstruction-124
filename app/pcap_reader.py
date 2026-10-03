"""Classic libpcap file parsing.

Supports both byte orders and microsecond/nanosecond timestamp resolution.
Only Ethernet frames are understood; only unfragmented IPv4/TCP packets are
emitted as TCP events. Everything else is counted as skipped.

Any truncation of the container file or of a captured packet raises
TruncatedPcap so callers can reject the whole upload without partial output.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

import dpkt

MAGIC_NS = 0xA1B23C4D
MAGIC_US = 0xA1B2A1B2

ETHERTYPE_VLAN = 0x8100
ETHERTYPE_IPV4 = 0x0800
IPPROTO_TCP = 6

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_ACK = 0x10


class PcapError(ValueError):
    """Malformed pcap container."""


class TruncatedPcap(PcapError):
    """File or packet bytes are cut short."""


@dataclass(frozen=True)
class TcpPacket:
    packet_no: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int
    payload: bytes
    ts_sec: int
    ts_frac: int  # nanoseconds


def _iter_raw_records(data: bytes):
    if len(data) < 24:
        raise TruncatedPcap("file shorter than 24-byte pcap global header")
    magic = struct.unpack("<I", data[:4])[0]
    if magic in (MAGIC_US, MAGIC_NS):
        endian = "<"
    else:
        be_magic = struct.unpack(">I", data[:4])[0]
        if be_magic in (MAGIC_US, MAGIC_NS):
            endian = ">"
        else:
            raise PcapError("not a classic pcap file (bad magic)")
    magic = struct.unpack(endian + "I", data[:4])[0]
    nano = magic == MAGIC_NS

    (version_major, version_minor, thiszone, sigfigs,
     snaplen, network) = struct.unpack(endian + "HHIIII", data[4:24])
    if (version_major, version_minor) != (2, 4):
        raise PcapError(
            f"unsupported pcap version {version_major}.{version_minor}"
        )
    if network != dpkt.pcap.DLT_EN10MB:
        raise PcapError(f"unsupported link type {network}; Ethernet only")
    if snaplen == 0:
        raise PcapError("invalid snaplen 0")

    offset = 24
    packet_no = 0
    total = len(data)
    while offset < total:
        if total - offset < 16:
            raise TruncatedPcap("truncated packet record header")
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(
            endian + "IIII", data[offset:offset + 16]
        )
        offset += 16
        packet_no += 1
        if incl_len > snaplen:
            raise PcapError(
                f"packet {packet_no}: captured length {incl_len} > snaplen"
            )
        if total - offset < incl_len:
            raise TruncatedPcap(f"packet {packet_no}: captured bytes missing")
        record = data[offset:offset + incl_len]
        offset += incl_len
        if len(record) < orig_len:
            # Frame itself was truncated on the wire relative to orig_len;
            # parsing below may still work, but link/IP/TCP length fields
            # must be fully present or it is a hard truncation error.
            pass
        yield packet_no, record, orig_len, ts_sec, ts_frac, nano


def parse_pcap(data: bytes):
    """Parse pcap bytes.

    Returns ``(tcp_packets, skipped)`` where skipped maps reason -> count.
    Raises PcapError/TruncatedPcap on malformed or truncated input.
    """
    skipped: dict[str, int] = {}

    def skip(reason: str) -> None:
        skipped[reason] = skipped.get(reason, 0) + 1

    tcp_packets: list[TcpPacket] = []
    for (packet_no, frame, orig_len, ts_sec, ts_frac,
         nano) in _iter_raw_records(data):
        if not nano:
            ts_frac *= 1000  # microseconds -> nanoseconds
        if len(frame) < orig_len:
            # Short frame on the wire: cannot trust contained headers unless
            # they are fully present; treat as truncation error per spec.
            raise TruncatedPcap(
                f"packet {packet_no}: frame truncated ({len(frame)} < "
                f"{orig_len} bytes on wire)"
            )
        try:
            eth = dpkt.ethernet.Ethernet(frame)
        except dpkt.NeedData as exc:
            raise TruncatedPcap(f"packet {packet_no}: {exc}") from exc
        except dpkt.UnpackError as exc:
            raise PcapError(f"packet {packet_no}: {exc}") from exc

        ethertype = eth.type
        if ethertype == ETHERTYPE_VLAN:
            # 802.1Q: skip tagged frames (no nested tag unwrapping needed for
            # the counted "other protocol" category).
            skip("vlan")
            continue
        if ethertype != ETHERTYPE_IPV4:
            skip("non_ipv4_ethertype")
            continue
        if not isinstance(eth.data, dpkt.ip.IP):
            skip("non_ipv4_ethertype")
            continue
        ip = eth.data
        if ip.v != 4:
            skip("non_ipv4_ethertype")
            continue
        if ip.mf or (ip.offset != 0):
            skip("fragmented_ipv4")
            continue
        if ip.p != IPPROTO_TCP:
            skip("non_tcp")
            continue
        if not isinstance(ip.data, dpkt.tcp.TCP):
            skip("non_tcp")
            continue
        tcp = ip.data
        payload = bytes(tcp.data)
        # Repack to force dpkt to derive header lengths, then re-parse so
        # data-offset/truncation checks operate on wire bytes.
        try:
            wire_ip = dpkt.ip.IP(bytes(ip))
        except dpkt.NeedData as exc:
            raise TruncatedPcap(f"packet {packet_no}: {exc}") from exc
        if not isinstance(wire_ip.data, dpkt.tcp.TCP):
            raise PcapError(f"packet {packet_no}: bad TCP header")
        tcp = wire_ip.data
        ip = wire_ip
        if tcp.off < 5:  # data offset in 32-bit words; minimum 5 (20 bytes)
            raise PcapError(f"packet {packet_no}: bad TCP data offset")
        payload = bytes(tcp.data)
        tcp_hdr_len = tcp.off * 4
        declared_tcp_len = wire_ip.len - wire_ip.hl * 4
        if declared_tcp_len < tcp_hdr_len:
            raise TruncatedPcap(
                f"packet {packet_no}: TCP header exceeds segment length"
            )
        if len(payload) > declared_tcp_len - tcp_hdr_len:
            raise TruncatedPcap(f"packet {packet_no}: TCP payload truncated")
        tcp_packets.append(
            TcpPacket(
                packet_no=packet_no,
                src_ip=".".join(str(b) for b in ip.src),
                dst_ip=".".join(str(b) for b in ip.dst),
                src_port=tcp.sport,
                dst_port=tcp.dport,
                seq=tcp.seq,
                ack=tcp.ack,
                flags=tcp.flags,
                payload=payload,
                ts_sec=ts_sec,
                ts_frac=ts_frac,
            )
        )
    return tcp_packets, skipped
