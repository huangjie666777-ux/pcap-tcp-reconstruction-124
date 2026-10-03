"""Connection tracking, generation split and byte-stream reassembly.

Connections are keyed by the unordered endpoint four-tuple. A generation starts
with a SYN without ACK. Each direction's sequence space is offset so that the
first data byte after that direction's own SYN is offset 0. SYN and FIN occupy
sequence numbers but yield no output. Offsets wrap modulo 2**32.

For overlapping data, the first bytes seen in file order win; conflicting
ranges and the packet numbers involved are recorded.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .pcap_reader import TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, TcpPacket

SEQ_SPACE = 1 << 32
SEQ_MASK = SEQ_SPACE - 1


class LimitExceeded(Exception):
    """A whole-file limit was exceeded; the upload must be rejected."""


@dataclass
class Segment:
    start: int  # inclusive offset
    end: int  # exclusive offset
    data: bytes
    packet_no: int


@dataclass
class DirectionState:
    syn_seq: int | None = None
    syn_packet: int | None = None
    synack_seen: bool = False  # SYN,ACK on this direction recorded
    fin_offset: int | None = None  # FIN occupies this offset
    fin_packet: int | None = None
    segments: list[Segment] = field(default_factory=list)
    sources: list[int] = field(default_factory=list)
    # conflict: {range_key: {"start", "end", "packets": sorted unique}}
    conflicts: list[dict] = field(default_factory=list)
    max_end: int = 0  # max payload end observed

    def _conflict(self, start: int, end: int, packets: list[int]) -> None:
        for conf in self.conflicts:
            if conf["start"] == start and conf["end"] == end:
                merged = sorted(set(conf["packets"]) | set(packets))
                conf["packets"] = merged
                return
        self.conflicts.append(
            {"start": start, "end": end, "packets": sorted(set(packets))}
        )

    def insert(self, start: int, end: int, data: bytes, packet_no: int,
               max_span: int) -> None:
        if end > max_span:
            raise LimitExceeded(
                f"direction span {end} exceeds limit {max_span}"
            )
        self.sources.append(packet_no)
        if end > self.max_end:
            self.max_end = end
        # Trim the new range against every existing segment. Overlapping
        # bytes are checked for conflicts and dropped (first-seen wins);
        # only uncovered sub-ranges are appended.
        pieces: list[tuple[int, int, bytes]] = [(start, end, data)]
        for seg in self.segments:
            surviving: list[tuple[int, int, bytes]] = []
            for piece_start, piece_end, piece_data in pieces:
                overlap_start = max(piece_start, seg.start)
                overlap_end = min(piece_end, seg.end)
                if overlap_start < overlap_end:
                    old = seg.data[
                        overlap_start - seg.start:overlap_end - seg.start
                    ]
                    new = piece_data[
                        overlap_start - piece_start:
                        overlap_end - piece_start
                    ]
                    if old != new:
                        self._conflict(
                            overlap_start, overlap_end,
                            [seg.packet_no, packet_no],
                        )
                    if piece_start < overlap_start:
                        surviving.append((
                            piece_start, overlap_start,
                            piece_data[:overlap_start - piece_start],
                        ))
                    if overlap_end < piece_end:
                        surviving.append((
                            overlap_end, piece_end,
                            piece_data[overlap_end - piece_start:],
                        ))
                else:
                    surviving.append((piece_start, piece_end, piece_data))
            pieces = surviving
            if not pieces:
                break
        self.segments.extend(
            Segment(s, e, d, packet_no) for s, e, d in pieces
        )

    def covered_intervals(self) -> list[list[int]]:
        if not self.segments:
            return []
        ordered = sorted(self.segments, key=lambda seg: seg.start)
        merged: list[list[int]] = []
        for seg in ordered:
            if merged and seg.start <= merged[-1][1]:
                if seg.end > merged[-1][1]:
                    merged[-1][1] = seg.end
            else:
                merged.append([seg.start, seg.end])
        return merged

    def gaps(self) -> list[list[int]]:
        limit = (
            self.fin_offset
            if self.fin_offset is not None
            else self.max_end
        )
        intervals = self.covered_intervals()
        result: list[list[int]] = []
        cursor = 0
        for start, end in intervals:
            if start > cursor and start <= limit:
                result.append([cursor, min(start, limit)])
            if end > cursor:
                cursor = end
            if cursor >= limit:
                break
        if cursor < limit:
            result.append([cursor, limit])
        return result

    def read(self, offset: int, length: int) -> bytes | None:
        """Return bytes or None if any part spans a gap."""
        return read_segments(
            [(s.start, s.end, s.data) for s in self.segments],
            offset, length,
        )


def read_segments(segments, offset: int, length: int) -> bytes | None:
    """Read contiguous bytes from ``(start, end, data)`` segments.

    Returns None when any part of ``[offset, offset+length)`` is uncovered.
    """
    if offset < 0 or length <= 0:
        raise ValueError("offset must be >= 0 and length > 0")
    end = offset + length
    out = bytearray()
    pos = offset
    for start, seg_end, data in sorted(segments, key=lambda item: item[0]):
        if seg_end <= pos:
            continue
        if start >= end:
            break
        if start > pos:
            return None
        take = data[pos - start:end - start]
        out.extend(take)
        pos += len(take)
        if pos >= end:
            break
    if pos < end:
        return None
    return bytes(out)


@dataclass
class Generation:
    gen_id: int
    initiator: tuple[str, int]
    responder: tuple[str, int]
    # dirs keyed by initiator->responder ("c2s") and responder->initiator
    c2s: DirectionState = field(default_factory=DirectionState)
    s2c: DirectionState = field(default_factory=DirectionState)
    close_reason: str | None = None  # "fin" | "rst" | None (superseded)
    first_packet: int = 0
    last_packet: int = 0

    def direction(self, src_ip: str, src_port: int) -> DirectionState:
        if (src_ip, src_port) == self.initiator:
            return self.c2s
        return self.s2c


def _conn_key(pkt: TcpPacket) -> frozenset:
    return frozenset(
        ((pkt.src_ip, pkt.src_port), (pkt.dst_ip, pkt.dst_port))
    )


def reassemble(
    packets: list[TcpPacket],
    max_generations: int = 200,
    max_span: int = 8 * 1024 * 1024,
) -> tuple[list[Generation], int]:
    """Build connections/generations from ordered TCP packets.

    Returns generations in file order plus the count of packets that had no
    opening SYN in their direction/generation. Raises LimitExceeded when a
    whole-file limit is exceeded.
    """
    # key -> list of generations (oldest first); last is active
    table: dict[frozenset, list[Generation]] = {}
    order: list[frozenset] = []
    gen_counter = 0
    missing_syn = 0

    def touch(gen: Generation, pkt: TcpPacket) -> None:
        gen.last_packet = pkt.packet_no

    for pkt in packets:
        key = _conn_key(pkt)
        gens = table.get(key)
        flags = pkt.flags
        is_syn = bool(flags & TCP_SYN)
        is_rst = bool(flags & TCP_RST)
        is_fin = bool(flags & TCP_FIN)

        if is_syn and not (flags & TCP_ACK):
            initiator = (pkt.src_ip, pkt.src_port)
            responder = (pkt.dst_ip, pkt.dst_port)
            new_gen = False
            if not gens:
                new_gen = True
            else:
                active = gens[-1]
                d = active.direction(pkt.src_ip, pkt.src_port)
                if active.close_reason is not None:
                    new_gen = True
                elif d.syn_seq is None:
                    # Should not normally happen for the initiator dir, but a
                    # bare SYN from the other endpoint also starts a new run.
                    new_gen = True
                elif (pkt.seq - d.syn_seq) & SEQ_MASK != 0:
                    new_gen = True
                # else: same sequence -> retransmission of the opening SYN
            if new_gen:
                gen_counter += 1
                if gen_counter > max_generations:
                    raise LimitExceeded(
                        f"generation count exceeds {max_generations}"
                    )
                gen = Generation(
                    gen_id=gen_counter,
                    initiator=initiator,
                    responder=responder,
                    first_packet=pkt.packet_no,
                )
                d = gen.c2s
                d.syn_seq = pkt.seq
                d.syn_packet = pkt.packet_no
                if key not in table:
                    table[key] = [gen]
                    order.append(key)
                else:
                    table[key].append(gen)
                touch(gen, pkt)
                continue
            # retransmitted opening SYN: just touch active generation
            touch(gens[-1], pkt)
            continue

        if not gens:
            missing_syn += 1
            continue
        gen = gens[-1]
        d = gen.direction(pkt.src_ip, pkt.src_port)

        if gen.close_reason is not None:
            # Packets after FIN/RST close do not belong to any open
            # generation; ignore (they are not missing-SYN orphans).
            continue

        if is_rst:
            # A reset closes the generation from either endpoint, even if
            # that direction never sent its own SYN (e.g. rejected SYN).
            gen.close_reason = "rst"
            touch(gen, pkt)
            continue

        if is_syn and (flags & TCP_ACK):
            # SYN,ACK establishes the responder direction's base, once.
            if d.syn_seq is None:
                d.syn_seq = pkt.seq
                d.syn_packet = pkt.packet_no
                d.synack_seen = True
            touch(gen, pkt)
            # SYN,ACK may also carry no payload; nothing further to do.

        if d.syn_seq is None:
            # Data/control before this direction's own SYN: orphan packet.
            missing_syn += 1
            touch(gen, pkt)
            continue

        base = d.syn_seq
        payload_len = len(pkt.payload)
        if payload_len:
            start = (pkt.seq - (base + 1)) & SEQ_MASK
            end = start + payload_len
            try:
                d.insert(start, end, pkt.payload, pkt.packet_no, max_span)
            except LimitExceeded:
                raise
        if is_fin:
            # FIN occupies one sequence number after the data, in the same
            # offset space (offset of a hypothetical byte at the FIN seq).
            d.fin_offset = (
                pkt.seq + payload_len - base - 1
            ) & SEQ_MASK
            d.fin_packet = pkt.packet_no
            other = gen.s2c if d is gen.c2s else gen.c2s
            if other.fin_offset is not None and gen.close_reason is None:
                gen.close_reason = "fin"
        touch(gen, pkt)

    generations: list[Generation] = []
    for key in order:
        generations.extend(table[key])
    return generations, missing_syn


def _dir_view(d: DirectionState) -> dict:
    return {
        "syn_packet": d.syn_packet,
        "known_intervals": d.covered_intervals(),
        "gaps": d.gaps(),
        "conflicts": d.conflicts,
        "source_packets": sorted(set(d.sources)),
        "fin_packet": d.fin_packet,
    }


def serialize_generations(generations: list[Generation]) -> list[dict]:
    result = []
    for gen in generations:
        result.append({
            "generation_id": gen.gen_id,
            "endpoints": {
                "initiator": {
                    "ip": gen.initiator[0], "port": gen.initiator[1]
                },
                "responder": {
                    "ip": gen.responder[0], "port": gen.responder[1]
                },
            },
            "close_reason": gen.close_reason,
            "first_packet": gen.first_packet,
            "last_packet": gen.last_packet,
            "initiator_to_responder": _dir_view(gen.c2s),
            "responder_to_initiator": _dir_view(gen.s2c),
        })
    return result
