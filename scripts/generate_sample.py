#!/usr/bin/env python3
"""Generate sample_capture.pcap exercising reassembly edge cases.

Layout (little-endian, nanosecond-resolution classic pcap):
  * connection 10.0.0.1:12345 <-> 10.0.0.2:80, two generations
  * generation 1: FIN close; c2s has retransmission, conflict, out-of-order
    fill and a final gap; s2c is contiguous
  * generation 2: RST close
  * skipped: ARP, UDP, fragmented IPv4/TCP
  * orphan TCP data packet with no preceding SYN
"""

from __future__ import annotations

import os
import struct

import dpkt

MAGIC_NS_LE = 0xA1B23C4D
DLT_EN10MB = 1

C_IP = bytes([10, 0, 0, 1])
S_IP = bytes([10, 0, 0, 2])
C_PORT = 12345
S_PORT = 80


def make_frame(src_ip, dst_ip, sport, dport, seq, ack, flags,
               payload=b"", mf=False):
    tcp = dpkt.tcp.TCP(
        sport=sport, dport=dport, seq=seq & 0xFFFFFFFF,
        ack=ack & 0xFFFFFFFF, flags=flags,
    )
    tcp.data = payload
    tcp.off = 5
    ip = dpkt.ip.IP(
        src=src_ip, dst=dst_ip, p=dpkt.ip.IP_PROTO_TCP,
        id=0x1234, mf=mf, ttl=64,
    )
    ip.data = tcp
    eth = dpkt.ethernet.Ethernet(
        src=b"\xaa\xbb\xcc\xdd\xee\x01",
        dst=b"\xaa\xbb\xcc\xdd\xee\x02",
        type=dpkt.ethernet.ETH_TYPE_IP,
    )
    eth.data = ip
    return bytes(eth)


def arp_frame():
    arp = dpkt.arp.ARP(
        spa=C_IP, tpa=S_IP,
        sha=b"\xaa\xbb\xcc\xdd\xee\x01",
        tha=b"\x00" * 6,
        op=dpkt.arp.ARP_OP_REQUEST,
    )
    eth = dpkt.ethernet.Ethernet(
        src=b"\xaa\xbb\xcc\xdd\xee\x01",
        dst=b"\xff" * 6,
        type=dpkt.ethernet.ETH_TYPE_ARP,
    )
    eth.data = arp
    return bytes(eth)


def udp_frame():
    udp = dpkt.udp.UDP(sport=5353, dport=53)
    udp.data = b"\x00" * 8
    ip = dpkt.ip.IP(src=C_IP, dst=S_IP, p=dpkt.ip.IP_PROTO_UDP, ttl=64)
    ip.data = udp
    eth = dpkt.ethernet.Ethernet(
        src=b"\xaa\xbb\xcc\xdd\xee\x01",
        dst=b"\xaa\xbb\xcc\xdd\xee\x02",
        type=dpkt.ethernet.ETH_TYPE_IP,
    )
    eth.data = ip
    return bytes(eth)


def write_pcap(path, records):
    # global header: ns magic, version 2.4, snaplen 65535, Ethernet
    header = struct.pack("<IHHIIII", MAGIC_NS_LE, 2, 4, 0, 0, 65535,
                         DLT_EN10MB)
    with open(path, "wb") as handle:
        handle.write(header)
        for idx, frame in enumerate(records, start=1):
            ts_sec = 1_700_000_000
            ts_ns = idx * 1000
            handle.write(struct.pack(
                "<IIII", ts_sec, ts_ns, len(frame), len(frame)
            ))
            handle.write(frame)


def main():
    TH_SYN = dpkt.tcp.TH_SYN
    TH_ACK = dpkt.tcp.TH_ACK
    TH_FIN = dpkt.tcp.TH_FIN
    TH_RST = dpkt.tcp.TH_RST
    TH_PUSH = dpkt.tcp.TH_PUSH

    c_seq, s_seq = 1000, 5000
    records = []

    # skipped noise first
    records.append(arp_frame())
    records.append(udp_frame())

    # generation 1 handshake
    records.append(make_frame(
        C_IP, S_IP, C_PORT, S_PORT, c_seq, 0, TH_SYN))
    records.append(make_frame(
        S_IP, C_IP, S_PORT, C_PORT, s_seq, c_seq + 1, TH_SYN | TH_ACK))
    records.append(make_frame(
        C_IP, S_IP, C_PORT, S_PORT, c_seq + 1, s_seq + 1, TH_ACK))

    # c2s first data, then later chunk arrives out of order, then middle fill
    records.append(make_frame(
        C_IP, S_IP, C_PORT, S_PORT, c_seq + 1, s_seq + 1,
        TH_PUSH | TH_ACK, b"0123456789"))
    records.append(make_frame(
        C_IP, S_IP, C_PORT, S_PORT, c_seq + 16, s_seq + 1,
        TH_PUSH | TH_ACK, b"PQRST"))
    # conflicting re-overlap: same range as PQRST, different bytes
    records.append(make_frame(
        C_IP, S_IP, C_PORT, S_PORT, c_seq + 16, s_seq + 1,
        TH_PUSH | TH_ACK, b"XXXXX"))
    # identical retransmission of the first 10 bytes
    records.append(make_frame(
        C_IP, S_IP, C_PORT, S_PORT, c_seq + 1, s_seq + 1,
        TH_PUSH | TH_ACK, b"0123456789"))
    # gap-fill for offsets 10..14
    records.append(make_frame(
        C_IP, S_IP, C_PORT, S_PORT, c_seq + 11, s_seq + 1,
        TH_PUSH | TH_ACK, b"KLMNO"))

    # fragmented TCP packet -> skipped
    records.append(make_frame(
        C_IP, S_IP, C_PORT, S_PORT, c_seq + 31, s_seq + 1,
        TH_PUSH | TH_ACK, b"FRAG", mf=True))

    # s2c contiguous response
    records.append(make_frame(
        S_IP, C_IP, S_PORT, C_PORT, s_seq + 1, c_seq + 1,
        TH_PUSH | TH_ACK, b"HELLO"))

    # c FIN at offset 30 (data never delivered offsets 20..29 -> gap)
    records.append(make_frame(
        C_IP, S_IP, C_PORT, S_PORT, c_seq + 31, s_seq + 1, TH_FIN | TH_ACK))
    records.append(make_frame(
        S_IP, C_IP, S_PORT, C_PORT, s_seq + 6, c_seq + 32, TH_ACK))
    # s FIN after HELLO (s FIN occupies offset 5)
    records.append(make_frame(
        S_IP, C_IP, S_PORT, C_PORT, s_seq + 6, c_seq + 32,
        TH_FIN | TH_ACK))
    records.append(make_frame(
        C_IP, S_IP, C_PORT, S_PORT, c_seq + 31, s_seq + 7, TH_ACK))

    # orphan TCP data on a connection that never sent a SYN
    records.append(make_frame(
        bytes([10, 0, 0, 9]), bytes([10, 0, 0, 10]), 9999, 8080,
        777, 0, TH_PUSH | TH_ACK, b"ORPHAN"))

    # generation 2: new SYN (new ISN) on the same four-tuple, reset quickly
    c_seq2 = 2000
    records.append(make_frame(
        C_IP, S_IP, C_PORT, S_PORT, c_seq2, 0, TH_SYN))
    records.append(make_frame(
        S_IP, C_IP, S_PORT, C_PORT, 9000, c_seq2 + 1, TH_RST))

    out_path = os.environ.get("SAMPLE_PCAP", "sample_capture.pcap")
    write_pcap(out_path, records)
    print(f"wrote {len(records)} packets to {out_path}")


if __name__ == "__main__":
    main()
