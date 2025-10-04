# main.py
from __future__ import annotations

import os
import time
import math
import statistics
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional, Tuple
from collections import deque, defaultdict, Counter
from contextlib import asynccontextmanager
from threading import Lock, Thread

from fastapi import FastAPI, Query
from pydantic import BaseModel

from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, conf  # type: ignore


# =========================
# Models
# =========================

class MetricsModel(BaseModel):
    bytes_ps: float
    pkts_ps: float
    udp_fraction: float
    tcp_fraction: float
    icmp_fraction: float
    mean_pkt_size: float
    tiny_pkt_fraction: float
    ttl_stdev: float
    syn_rate: float
    syn_ack_ratio: float
    half_open_conn_count: int
    avg_bytes_per_flow: float
    new_conn_rate: float
    peak_to_avg_rate: float


# =========================
# Sliding-window metrics
# =========================

@dataclass
class _FlowState:
    first: float
    last: float
    bytes: int
    syn_seen: bool
    ack_seen: bool
    closed: bool


class PacketStats:
    def __init__(self, window_secs: int = 30, tiny_pkt_threshold: int = 100):
        self.window_secs = window_secs
        self.tiny_pkt_threshold = tiny_pkt_threshold
        self.events: Deque[dict] = deque()
        self.flows: Dict[Tuple[str, int, str, int, str], _FlowState] = {}
        self.new_flow_times: Deque[float] = deque()
        self.new_tcp_conns: Deque[float] = deque()
        self.byte_bins: Dict[int, int] = defaultdict(int)

    @staticmethod
    def _entropy(counter: Counter) -> float:
        n = sum(counter.values())
        if n <= 1:
            return 0.0
        return -sum((c / n) * math.log2(c / n) for c in counter.values())

    def _prune(self, now: float):
        cutoff = now - self.window_secs
        while self.events and self.events[0]["ts"] < cutoff:
            self.events.popleft()
        while self.new_flow_times and self.new_flow_times[0] < cutoff:
            self.new_flow_times.popleft()
        while self.new_tcp_conns and self.new_tcp_conns[0] < cutoff:
            self.new_tcp_conns.popleft()
        min_bin = int(now) - self.window_secs + 1
        for sec in list(self.byte_bins.keys()):
            if sec < min_bin:
                del self.byte_bins[sec]
        self.flows = {
            fid: st
            for fid, st in self.flows.items()
            if (st.last >= cutoff) or (not st.closed)
        }

    def update(self, pkt, now: Optional[float] = None) -> MetricsModel:
        if now is None:
            now = time.time()
        if IP not in pkt:
            return self._snapshot(now)

        ip = pkt[IP]
        ttl = getattr(ip, "ttl", None)
        size = len(bytes(pkt))

        if TCP in pkt:
            proto = "TCP"
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            flags = int(pkt[TCP].flags)
            is_syn = bool(flags & 0x02) and not bool(flags & 0x10)
            is_synack = (flags & 0x12) == 0x12
            fin_or_rst = bool(flags & 0x01) or bool(flags & 0x04)
        elif UDP in pkt:
            proto = "UDP"
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
            is_syn = is_synack = fin_or_rst = False
        elif ICMP in pkt:
            proto = "ICMP"
            sport = dport = 0
            is_syn = is_synack = fin_or_rst = False
        else:
            proto = "OTHER"
            sport = dport = 0
            is_syn = is_synack = fin_or_rst = False

        fid = (str(ip.src), sport, str(ip.dst), dport, proto)
        st = self.flows.get(fid)
        if st is None:
            st = self.flows[fid] = _FlowState(
                first=now, last=now, bytes=0, syn_seen=False, ack_seen=False, closed=False
            )
            self.new_flow_times.append(now)
            if proto == "TCP" and is_syn:
                self.new_tcp_conns.append(now)
        else:
            st.last = now
        st.bytes += size
        if proto == "TCP":
            if is_syn:
                st.syn_seen = True
            if (int(pkt[TCP].flags) & 0x10) and not (int(pkt[TCP].flags) & 0x02):
                st.ack_seen = True
            if fin_or_rst:
                st.closed = True

        self.events.append(
            {
                "ts": now,
                "size": size,
                "proto": proto,
                "src_ip": str(ip.src),
                "src_port": sport,
                "ttl": ttl if ttl is not None else None,
                "flow": fid,
                "is_syn": is_syn,
                "is_synack": is_synack,
            }
        )
        self.byte_bins[int(now)] += size
        self._prune(now)
        return self._snapshot(now)

    def _snapshot(self, now: float) -> MetricsModel:
        evs = list(self.events)
        n = len(evs)
        total_bytes = sum(e["size"] for e in evs)
        w = max(self.window_secs, 1)
        bytes_ps = total_bytes / w
        pkts_ps = n / w
        new_conn_rate = len(self.new_tcp_conns) / w

        proto_counts = Counter(e["proto"] for e in evs)
        denom = n if n else 1
        udp_fraction = proto_counts["UDP"] / denom
        tcp_fraction = proto_counts["TCP"] / denom
        icmp_fraction = proto_counts["ICMP"] / denom

        src_ips = [e["src_ip"] for e in evs]
        unique_src_ips = len(set(src_ips))
       
        src_ports = [e["src_port"] for e in evs if e["src_port"]]
        

        mean_pkt_size = (total_bytes / n) if n else 0.0
        tiny_pkt_fraction = (
            sum(1 for e in evs if e["size"] < self.tiny_pkt_threshold) / denom
        )

        ttl_vals = [e["ttl"] for e in evs if isinstance(e["ttl"], (int, float))]
        ttl_stdev = statistics.stdev(ttl_vals) if len(ttl_vals) >= 2 else 0.0

        syn_cnt = sum(1 for e in evs if e["is_syn"])
        synack_cnt = sum(1 for e in evs if e["is_synack"])
        syn_rate = syn_cnt / w
        syn_ack_ratio = (synack_cnt / syn_cnt) if syn_cnt else 0.0

        active_flows: Dict[Tuple[str, int, str, int, str], _FlowState] = {}
        for e in evs:
            st = self.flows.get(e["flow"])
            if st:
                active_flows[e["flow"]] = st

        half_open_conn_count = sum(
            1
            for fid, st in active_flows.items()
            if ("TCP" in fid) and st.syn_seen and not st.ack_seen
        )
        avg_bytes_per_flow = (
            total_bytes / len(active_flows) if active_flows else 0.0
        )

        min_bin = int(now) - self.window_secs + 1
        bins = [v for sec, v in self.byte_bins.items() if sec >= min_bin]
        if bins:
            avg_bps = sum(bins) / len(bins)
            peak_bps = max(bins)
            peak_to_avg_rate = (peak_bps / avg_bps) if avg_bps > 0 else 0.0
        else:
            peak_to_avg_rate = 0.0

        times = [e["ts"] for e in evs]
        if len(times) >= 3:
            iats = [t2 - t1 for t1, t2 in zip(times, times[1:]) if t2 >= t1]
            if iats:
                mean_iat = sum(iats) / len(iats)
                std_iat = statistics.stdev(iats) if len(iats) >= 2 else 0.0

        return MetricsModel(
            bytes_ps=bytes_ps,
            pkts_ps=pkts_ps,
            unique_src_ips=unique_src_ips,
            udp_fraction=udp_fraction,
            tcp_fraction=tcp_fraction,
            icmp_fraction=icmp_fraction,
            mean_pkt_size=mean_pkt_size,
            tiny_pkt_fraction=tiny_pkt_fraction,
            ttl_stdev=ttl_stdev,
            syn_rate=syn_rate,
            syn_ack_ratio=syn_ack_ratio,
            half_open_conn_count=half_open_conn_count,
            avg_bytes_per_flow=avg_bytes_per_flow,
            new_conn_rate=new_conn_rate,
            peak_to_avg_rate=peak_to_avg_rate,
        )


# =========================
# Sniffer + 5s sampler
# =========================

def _find_iface_by_ip(ipv4: str) -> Optional[str]:
    for _, iface in conf.ifaces.items():
        if getattr(iface, "ip", None) == ipv4:
            return getattr(iface, "pcap_name", None) or getattr(iface, "name", None)
    return None


class ThreadedSniffer:
    def __init__(
        self,
        bpf_filter: str = os.getenv("BPF_FILTER", "ip"),
        iface: Optional[str] = None,
        iface_ip: str = os.getenv("SNIFF_IFACE_IP", "192.168.10.2"),
        window_secs: int = int(os.getenv("WINDOW_SECS", "30")),
        metrics_interval_secs: int = int(os.getenv("METRICS_INTERVAL_SECS", "5")),
        metrics_history_bins: int = int(os.getenv("METRICS_HISTORY_BINS", "120")),  # ~10 min @5s
    ):
        self.bpf_filter = bpf_filter
        self.iface = iface or _find_iface_by_ip(iface_ip)
        self.metrics = PacketStats(window_secs=window_secs)

        # metrics time-series (5s cadence)
        self.metrics_interval_secs = max(1, metrics_interval_secs)
        self.metrics_series: Deque[MetricsModel] = deque(maxlen=metrics_history_bins)

        self.lock = Lock()
        self._sniffer: Optional[AsyncSniffer] = None
        self._sampler_thread: Optional[Thread] = None
        self._sampler_running: bool = False

    @staticmethod
    def _classify_proto(pkt) -> str:
        if ICMP in pkt:
            return "ICMP"
        if TCP in pkt:
            return "TCP"
        if UDP in pkt:
            return "UDP"
        return "OTHER"

    def _handle_packet(self, pkt) -> None:
        if IP not in pkt:
            return
        # keep metrics updated for every packet
        self.metrics.update(pkt, time.time())
        print(pkt.summary())

    # ---- sampler that snapshots metrics every 5s (aligned to wall clock)
    def _sampler_loop(self):
        interval = self.metrics_interval_secs
        while self._sampler_running:
            now = time.time()
            # align to next boundary (e.g., 00:00:05, :10, :15, ...)
            next_tick = math.floor(now / interval) * interval + interval
            sleep_for = max(0.0, next_tick - time.time())
            time.sleep(sleep_for)
            snap = self.metrics._snapshot(time.time())
            with self.lock:
                self.metrics_series.append(snap)
                print(snap)

    def start(self):
        if not self.iface:
            raise RuntimeError(
                "No sniffing interface resolved. Set SNIFF_IFACE or SNIFF_IFACE_IP."
            )
        self._sniffer = AsyncSniffer(
            iface=self.iface, filter=self.bpf_filter, prn=self._handle_packet, store=False
        )
        self._sniffer.start()

        self._sampler_running = True
        self._sampler_thread = Thread(target=self._sampler_loop, daemon=True)
        self._sampler_thread.start()

    def stop(self):
        if self._sniffer:
            try:
                self._sniffer.stop()
            finally:
                self._sniffer = None
        self._sampler_running = False
        if self._sampler_thread:
            self._sampler_thread.join(timeout=1.0)
            self._sampler_thread = None

    def get_metrics_series(self, bins: int) -> List[MetricsModel]:
        with self.lock:
            series = list(self.metrics_series)
        if bins:
            series = series[-bins:]
        return series


# =========================
# FastAPI app — ONLY /packets
# =========================

sniffer = ThreadedSniffer(
    bpf_filter=os.getenv("BPF_FILTER", "ip"),          # use "icmp" to only process ICMP
    iface=os.getenv("SNIFF_IFACE", None),             # r"\\Device\\NPF_{GUID}" or "Ethernet 2"
    iface_ip=os.getenv("SNIFF_IFACE_IP", "192.168.10.2"),
    window_secs=int(os.getenv("WINDOW_SECS", "30")),
    metrics_interval_secs=int(os.getenv("METRICS_INTERVAL_SECS", "5")),
    metrics_history_bins=int(os.getenv("METRICS_HISTORY_BINS", "120")),
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    sniffer.start()
    try:
        yield
    finally:
        sniffer.stop()

app = FastAPI(lifespan=lifespan)


# Returns ONLY the metrics, as an array sampled every 5 seconds.
@app.get("/packets", response_model=List[MetricsModel])
def get_packets(
    bins: int = Query(12, ge=1, le=720, description="How many 5-second samples to return (default 12 = last 60s)."),
):
    return sniffer.get_metrics_series(bins=bins)
