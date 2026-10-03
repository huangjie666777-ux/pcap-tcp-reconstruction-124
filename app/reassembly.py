"""TCP 连接分代与按序号字节重组（支持 32 位回绕）。"""

from __future__ import annotations

from dataclasses import dataclass, field

import dpkt

from .pcap_reader import TcpPacket

SEQ_MOD = 1 << 32
MAX_SPAN = 8 * 1024 * 1024
MAX_GENERATIONS = 200

TH_FIN = dpkt.tcp.TH_FIN
TH_SYN = dpkt.tcp.TH_SYN
TH_RST = dpkt.tcp.TH_RST
TH_ACK = dpkt.tcp.TH_ACK


class ReassemblyError(ValueError):
    """重组过程中发现语义非法的报文序列。"""


class LimitError(ReassemblyError):
    """超过代/跨度限制，整份文件拒绝。"""


def seq_delta(seq: int, base: int) -> int:
    """返回 seq 相对 base 的有符号 32 位差值。"""
    d = (seq - base) & 0xFFFFFFFF
    return d - SEQ_MOD if d >= (SEQ_MOD >> 1) else d


def _merge_runs(flags: bytearray, span: int) -> list[list[int]]:
    runs: list[list[int]] = []
    start = -1
    for i in range(span):
        if flags[i] and start < 0:
            start = i
        elif not flags[i] and start >= 0:
            runs.append([start, i])
            start = -1
    if start >= 0:
        runs.append([start, span])
    return runs


@dataclass
class Conflict:
    start: int
    end: int
    packets: list[int]

    def to_dict(self) -> dict:
        return {"start": self.start, "end": self.end, "packets": self.packets}


@dataclass
class DirectionStream:
    name: str
    isn: int | None = None
    syn_ts: float | None = None
    _buf: bytearray = field(default_factory=bytearray)
    _have: bytearray = field(default_factory=bytearray)
    _segments: list[tuple[int, int, int]] = field(default_factory=list)
    _conflicts: list[Conflict] = field(default_factory=list)
    _max_data_end: int = 0
    fin_pos: int | None = None
    fin_seen: bool = False
    packet_numbers: set[int] = field(default_factory=set)
    retransmissions: int = 0

    def init_isn(self, isn: int, ts: float) -> bool:
        """登记 SYN。返回 False 表示同序号重传（已建立）。"""
        if self.isn is None:
            self.isn = isn
            self.syn_ts = ts
            return True
        return isn == self.isn

    def _ensure(self, size: int) -> None:
        if size > MAX_SPAN:
            raise LimitError(
                f"方向 {self.name} 数据跨度 {size} 字节超过 {MAX_SPAN} 字节限制"
            )
        if size > len(self._buf):
            grow = size - len(self._buf)
            self._buf.extend(b"\x00" * grow)
            self._have.extend(b"\x00" * grow)

    def add_data(self, seq: int, data: bytes, pkt_no: int) -> None:
        if not data or self.isn is None:
            return
        # 相对 ISN：SYN 占序号 0，首数据字节相对偏移 0
        start = seq_delta(seq, (self.isn + 1) & 0xFFFFFFFF)
        if start < 0:
            raise ReassemblyError(f"包 {pkt_no} 数据落在 SYN 之前")
        end = start + len(data)
        self._ensure(end)

        conflict_flags = bytearray(end - start)
        overlapping = False
        identical = True
        for i in range(start, end):
            b = data[i - start]
            if self._have[i]:
                overlapping = True
                if self._buf[i] != b:
                    identical = False
                    conflict_flags[i - start] = 1
            else:
                self._buf[i] = b
                self._have[i] = 1

        owners = {pkt_no}
        conflict_run_start = -1
        for j, flagged in enumerate(conflict_flags):
            i = start + j
            if flagged:
                if conflict_run_start < 0:
                    conflict_run_start = i
                    owners = {pkt_no}
                for seg_start, seg_end, seg_pkt in self._segments:
                    if seg_start <= i < seg_end:
                        owners.add(seg_pkt)
            elif conflict_run_start >= 0:
                self._conflicts.append(Conflict(conflict_run_start, i, sorted(owners)))
                conflict_run_start = -1
        if conflict_run_start >= 0:
            self._conflicts.append(Conflict(conflict_run_start, end, sorted(owners)))

        # _segments 尚未加入本包；存在完全相同的重叠即为重传
        if overlapping and identical:
            self.retransmissions += 1
        self._segments.append((start, end, pkt_no))
        self._segments.sort(key=lambda item: item[0])
        self.packet_numbers.add(pkt_no)
        if end > self._max_data_end:
            self._max_data_end = end

    def mark_fin(self, seq: int, data_len: int) -> None:
        if self.isn is None:
            return
        # FIN 序号相对首字节基址 isn+1 => 数据 exclusive-end 位置
        pos = seq_delta(
            (seq + data_len) & 0xFFFFFFFF, (self.isn + 1) & 0xFFFFFFFF
        )
        if pos < 0:
            raise ReassemblyError("FIN 落在 SYN 之前")
        self.fin_seen = True
        self.fin_pos = pos if self.fin_pos is None else max(self.fin_pos, pos)

    @property
    def span_end(self) -> int:
        if self.fin_seen:
            return max(self.fin_pos or 0, self._max_data_end)
        return self._max_data_end

    def payload(self) -> bytes:
        return bytes(self._buf[: self.span_end])

    def gap_flags(self) -> bytearray:
        span = self.span_end
        flags = bytearray(span)
        for i in range(min(span, len(self._have))):
            if not self._have[i]:
                flags[i] = 1
        for i in range(len(self._have), span):
            flags[i] = 1
        return flags

    def to_dict(self) -> dict:
        span = self.span_end
        known = _merge_runs(self._have, span)
        gaps = _merge_runs(self.gap_flags(), span)
        return {
            "isn": self.isn,
            "syn_ts": self.syn_ts,
            "span": span,
            "known_intervals": known,
            "gaps": gaps,
            "conflicts": [c.to_dict() for c in self._conflicts],
            "packet_numbers": sorted(self.packet_numbers),
            "retransmissions": self.retransmissions,
            "fin_seen": self.fin_seen,
        }


CLOSE_FIN = "fin"
CLOSE_RST = "rst"
CLOSE_SUPERSEDED = "superseded"
CLOSE_OPEN = "open"


@dataclass
class Generation:
    index: int
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    c2s: DirectionStream = field(default_factory=lambda: DirectionStream("c2s"))
    s2c: DirectionStream = field(default_factory=lambda: DirectionStream("s2c"))
    close_reason: str = CLOSE_OPEN
    first_ts: float | None = None
    last_ts: float | None = None
    closed: bool = False

    def direction_for(self, pkt: TcpPacket) -> DirectionStream | None:
        if (
            (pkt.src_ip, pkt.src_port) == (self.client_ip, self.client_port)
            and (pkt.dst_ip, pkt.dst_port) == (self.server_ip, self.server_port)
        ):
            return self.c2s
        if (
            (pkt.src_ip, pkt.src_port) == (self.server_ip, self.server_port)
            and (pkt.dst_ip, pkt.dst_port) == (self.client_ip, self.client_port)
        ):
            return self.s2c
        return None

    def note_ts(self, ts: float) -> None:
        if self.first_ts is None:
            self.first_ts = ts
        self.last_ts = ts

    def close(self, reason: str) -> None:
        if not self.closed:
            self.close_reason = reason
            self.closed = True


@dataclass
class ReassemblyResult:
    generations: list[Generation]
    orphan_packets: int
    skipped: dict[str, int]
    total_packets: int
    tcp_packets: int


class Reassembler:
    def __init__(self) -> None:
        self.generations: list[Generation] = []
        self._active: dict[tuple, Generation] = {}
        self.orphan_packets = 0

    def _new_generation(self, pkt: TcpPacket) -> Generation:
        if len(self.generations) >= MAX_GENERATIONS:
            raise LimitError(
                f"连接代数 {len(self.generations) + 1} 超过 {MAX_GENERATIONS} 上限"
            )
        gen = Generation(
            index=len(self.generations),
            client_ip=pkt.src_ip,
            client_port=pkt.src_port,
            server_ip=pkt.dst_ip,
            server_port=pkt.dst_port,
        )
        self.generations.append(gen)
        key = self._key(pkt)
        old = self._active.get(key)
        if old is not None and not old.closed:
            old.close(CLOSE_SUPERSEDED)
        self._active[key] = gen
        return gen

    @staticmethod
    def _key(pkt: TcpPacket) -> tuple:
        a = (pkt.src_ip, pkt.src_port)
        b = (pkt.dst_ip, pkt.dst_port)
        return tuple(sorted((a, b)))

    def handle(self, pkt: TcpPacket) -> None:
        flags = pkt.flags
        syn = bool(flags & TH_SYN)
        ack = bool(flags & TH_ACK)
        rst = bool(flags & TH_RST)
        fin = bool(flags & TH_FIN)
        key = self._key(pkt)
        active = self._active.get(key)

        if syn and not ack:
            gen = active
            if (
                gen is not None
                and not gen.closed
                and gen.client_ip == pkt.src_ip
                and gen.client_port == pkt.src_port
                and gen.c2s.isn == pkt.seq
            ):
                gen.note_ts(pkt.ts)  # 同序号 SYN：重传
                return
            gen = self._new_generation(pkt)
            gen.c2s.init_isn(pkt.seq, pkt.ts)
            gen.note_ts(pkt.ts)
            if rst:  # 畸形但容错：按 RST 关闭
                gen.close(CLOSE_RST)
            return

        if syn and ack:
            if rst and active is not None and not active.closed:
                active.note_ts(pkt.ts)
                active.close(CLOSE_RST)
                return
            if (
                active is None
                or active.closed
                or active.client_ip != pkt.dst_ip
                or active.client_port != pkt.dst_port
            ):
                self.orphan_packets += 1
                return
            if not active.s2c.init_isn(pkt.seq, pkt.ts):
                # 新序号 SYN+ACK 不属于既有代，按孤儿计数
                self.orphan_packets += 1
                return
            active.note_ts(pkt.ts)
            if pkt.payload:
                active.s2c.add_data(pkt.seq, pkt.payload, pkt.packet_no)
            if rst:
                active.close(CLOSE_RST)
            elif fin:
                active.s2c.mark_fin(pkt.seq, len(pkt.payload))
            return

        if active is None or active.closed:
            self.orphan_packets += 1
            return
        direction = active.direction_for(pkt)
        if direction is None:
            self.orphan_packets += 1
            return

        active.note_ts(pkt.ts)
        if rst and direction.isn is None:
            # 对端在 SYN+ACK 前直接 RST，仍关闭活动代
            active.close(CLOSE_RST)
            return
        if direction.isn is None:
            self.orphan_packets += 1
            return
        if pkt.payload:
            direction.add_data(pkt.seq, pkt.payload, pkt.packet_no)
        if fin:
            direction.mark_fin(pkt.seq, len(pkt.payload))
            other = active.s2c if direction is active.c2s else active.c2s
            if other.fin_seen:
                active.close(CLOSE_FIN)
        if rst:
            active.close(CLOSE_RST)

    def finalize(self) -> None:
        for gen in self.generations:
            if not gen.closed:
                gen.close(CLOSE_OPEN)


def reassemble(packets: list[TcpPacket], stats) -> ReassemblyResult:
    engine = Reassembler()
    for pkt in packets:
        engine.handle(pkt)
    engine.finalize()
    return ReassemblyResult(
        generations=engine.generations,
        orphan_packets=engine.orphan_packets,
        skipped=dict(stats.skipped),
        total_packets=stats.total_packets,
        tcp_packets=stats.tcp_packets,
    )
