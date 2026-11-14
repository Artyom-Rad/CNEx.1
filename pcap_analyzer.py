"""pcap_analyzer.py - Extracts data and HTTP transactions from PCAP / PCAPNG files (FR-1..FR-7).

Note: HTTP analysis relies on simple TCP segment reassembly (no chunked/gzip decoding, no HTTPS decryption).
"""
from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone

import pandas as pd
from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Ether, IPv6, PcapReader, Raw

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
                b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ")
BODY_LIMIT = 4000  # max number of body bytes stored per message


@dataclass
class PcapResult:
    packets: pd.DataFrame
    transactions: pd.DataFrame
    tx_details: dict          # tx_id -> dict with headers and full content
    summary: dict
    warnings: list = field(default_factory=list)


# ---------------------------------------------------------------- HTTP state
class _HttpState:
    def __init__(self):
        self.buffers = {}       # dir_key -> {"frame","time","data"}
        self.last_msg = {}      # dir_key -> (tx, field_name)
        self.pending = {}       # conn_key -> deque[tx]
        self.txs = []
        self.unmatched_responses = 0
        self.seen = set()       # (dir_key, seq) - filters out retransmissions

    def feed(self, frame, ts, src, sport, dst, dport, seq, payload) -> bool:
        dk = (src, sport, dst, dport)
        if (dk, seq) in self.seen:
            return False
        self.seen.add((dk, seq))

        starts_new = payload.startswith(HTTP_METHODS) or payload.startswith(b"HTTP/")
        buf = self.buffers.get(dk)
        if starts_new:
            if buf:
                self._finalize(dk, buf)
            buf = {"frame": frame, "time": ts, "data": payload}
            self.buffers[dk] = buf
        elif buf:
            buf["data"] += payload
        else:
            last = self.last_msg.get(dk)       # continuation of a previous message body
            if last:
                tx, fld = last
                room = BODY_LIMIT - len(tx[fld])
                if room > 0:
                    tx[fld] += payload[:room]
            return False

        if b"\r\n\r\n" in buf["data"]:
            self._finalize(dk, buf)
        return True

    def flush(self):
        for dk, buf in list(self.buffers.items()):
            self._finalize(dk, buf)

    def _finalize(self, dk, buf):
        self.buffers.pop(dk, None)
        head_b, _, body_b = buf["data"].partition(b"\r\n\r\n")
        lines = head_b.decode("latin-1", errors="replace").split("\r\n")
        first = lines[0].strip()
        if not first:
            return
        headers = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        head_text = "\r\n".join(lines)
        body_b = body_b[:BODY_LIMIT]
        src, sport, dst, dport = dk

        if first.startswith("HTTP/"):
            parts = first.split(" ", 2)
            try:
                status = int(parts[1])
            except (IndexError, ValueError):
                status = None
            reason = parts[2] if len(parts) > 2 else ""
            queue = self.pending.get((dst, dport, src, sport))
            if not queue:
                self.unmatched_responses += 1
                return
            tx = queue.popleft()
            tx.update(resp_frame=buf["frame"], resp_time=buf["time"], status=status,
                      reason=reason, resp_head=head_text, resp_body=body_b,
                      response_time_ms=round((buf["time"] - tx["req_time"]) * 1000, 3))
            self.last_msg[dk] = (tx, "resp_body")
        else:
            parts = first.split(" ")
            tx = dict(
                id=len(self.txs) + 1, method=parts[0],
                uri=parts[1] if len(parts) > 1 else None,
                host=headers.get("host"),
                src_ip=src, src_port=sport, dst_ip=dst, dst_port=dport,
                req_frame=buf["frame"], req_time=buf["time"],
                req_head=head_text, req_body=body_b,
                resp_frame=None, resp_time=None, status=None, reason=None,
                resp_head=None, resp_body=b"", response_time_ms=None)
            self.txs.append(tx)
            self.pending.setdefault(dk, deque()).append(tx)
            self.last_msg[dk] = (tx, "req_body")


# ---------------------------------------------------------------- packets
def _addrs(pkt):
    if pkt.haslayer(IP):
        return pkt[IP].src, pkt[IP].dst
    if pkt.haslayer(IPv6):
        return pkt[IPv6].src, pkt[IPv6].dst
    if pkt.haslayer(ARP):
        return pkt[ARP].psrc, pkt[ARP].pdst
    if pkt.haslayer(Ether):
        return pkt[Ether].src, pkt[Ether].dst
    return "N/A", "N/A"


def _process_packet(idx, pkt, http: _HttpState):
    ts = float(pkt.time)
    src, dst = _addrs(pkt)
    sport = dport = None
    proto = "Other"
    if pkt.haslayer(TCP):
        sport, dport, proto = pkt[TCP].sport, pkt[TCP].dport, "TCP"
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            if payload and http.feed(idx, ts, src, sport, dst, dport, pkt[TCP].seq, payload):
                proto = "HTTP"
    elif pkt.haslayer(UDP):
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
        proto = "DNS" if pkt.haslayer(DNS) else "UDP"
    elif pkt.haslayer(ICMP):
        proto = "ICMP"
    elif pkt.haslayer(ARP):
        proto = "ARP"
    else:
        proto = pkt.lastlayer().name or "Other"
    return dict(frame=idx, time=ts, length=len(pkt), src=src, dst=dst,
                sport=sport, dport=dport, protocol=proto)


def _fmt(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f UTC")


def _text(b: bytes) -> str:
    return b.decode("utf-8", errors="replace")


# ---------------------------------------------------------------- public API
def analyze_pcap(path: str) -> PcapResult:
    rows, warnings = [], []
    http = _HttpState()
    try:
        with PcapReader(path) as reader:
            for idx, pkt in enumerate(reader, start=1):
                try:
                    rows.append(_process_packet(idx, pkt, http))
                except Exception as e:  # a single corrupt packet - keep going
                    warnings.append(f"Packet {idx} skipped: {e}")
    except Exception as e:  # corrupt / truncated file - use what was read
        warnings.append(f"Error reading the file (it may be corrupt or truncated): {e}")
    http.flush()

    if not rows:
        raise ValueError("No packets could be read from the file. Make sure it is a valid PCAP/PCAPNG file.")

    pk = pd.DataFrame(rows)
    start, end = pk["time"].min(), pk["time"].max()

    talkers = Counter()
    for s, d in zip(pk["src"], pk["dst"]):
        talkers[s] += 1
        talkers[d] += 1
    summary = dict(
        total_packets=len(pk), total_bytes=int(pk["length"].sum()),
        start_time=_fmt(start), end_time=_fmt(end),
        start_epoch=start, end_epoch=end, duration_sec=round(end - start, 6),
        top_talkers=talkers.most_common(10),
        protocols=pk["protocol"].value_counts().to_dict(),
    )

    if http.unmatched_responses:
        warnings.append(f"{http.unmatched_responses} HTTP responses had no matching request in the capture.")

    tx_rows, details = [], {}
    for t in http.txs:
        tx_rows.append({
            "ID": t["id"], "Method": t["method"], "Host": t["host"], "URI": t["uri"],
            "Src IP": t["src_ip"], "Src Port": t["src_port"],
            "Dst IP": t["dst_ip"], "Dst Port": t["dst_port"],
            "Status": t["status"], "Response Time (ms)": t["response_time_ms"],
            "Request Frame": t["req_frame"], "Response Frame": t["resp_frame"],
            "Request Time": _fmt(t["req_time"]),
        })
        details[t["id"]] = dict(
            req_head=t["req_head"], req_body=_text(t["req_body"]),
            resp_head=t["resp_head"], resp_body=_text(t["resp_body"]))
    tx_df = pd.DataFrame(tx_rows)
    summary["http_transactions"] = len(tx_df)
    summary["unanswered_requests"] = int(tx_df["Status"].isna().sum()) if len(tx_df) else 0

    return PcapResult(pk, tx_df, details, summary, warnings)