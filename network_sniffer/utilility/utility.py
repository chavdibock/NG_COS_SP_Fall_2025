from typing import Dict, List
from schemas.schemas import Metrics
from threading import Lock, Event, Thread
from scapy.all import sniff, IP, TCP
import time
import math

STORE: Dict[str, List[Metrics]] = {}
STORE_LOCK = Lock()

CAPTURE_STOP: Dict[str, Event] = {}
CAPTURE_THREADS: Dict[str, Thread] = {}
CAPTURE_LOCK = Lock()


class Capture:
    def stdev(nums: List[float]) -> float:
        if not nums:
            return 0.0
        m = sum(nums) / len(nums)
        var = sum((x - m) ** 2 for x in nums) / len(nums)
        return math.sqrt(var)

    def capture_loop_5s(target_ip: str, stop_evt: Event) -> None:
        """
        Continuously capture traffic for `target_ip` in 5-second windows
        until `stop_evt` is set. Each window produces one metrics record.
        """
        try:
            while not stop_evt.is_set():
                interval_start = time.time()

                total_bytes = 0
                total_pkts = 0

                tcp_cnt = 0
                sizes_tiny = 0
                pkt_sizes: List[int] = []
                ttls: List[int] = []
                bytes_per_sec = [0, 0, 0, 0, 0]
                flows = set()
                syn_count = 0
                synack_count = 0
                syn_flows = set()
                new_conn_flows = set()

                def on_pkt(pkt):
                    nonlocal total_bytes, total_pkts, tcp_cnt
                    nonlocal sizes_tiny, pkt_sizes, ttls, bytes_per_sec, flows
                    nonlocal syn_count, synack_count, syn_flows, new_conn_flows

                    if IP not in pkt:
                        return

                    total_pkts += 1
                    size = len(pkt)
                    total_bytes += size
                    pkt_sizes.append(size)
                    if size <= 64:
                        sizes_tiny += 1

                    sec = int(time.time() - interval_start)
                    if 0 <= sec < 5:
                        bytes_per_sec[sec] += size

                    try:
                        ttls.append(int(pkt[IP].ttl))
                    except Exception:
                        pass

                    proto = "OTHER"
                    sport = dport = None

                    if TCP in pkt:
                        tcp_cnt += 1
                        proto = "TCP"
                        sport = int(pkt[TCP].sport)
                        dport = int(pkt[TCP].dport)
                        flags = int(pkt[TCP].flags)

                        # SYN without ACK (new connection attempt)
                        if (flags & 0x02) and not (flags & 0x10):
                            syn_count += 1
                            f = (pkt[IP].src, sport, pkt[IP].dst, dport)
                            syn_flows.add(f)
                            new_conn_flows.add(f)

                        # SYN+ACK
                        if (flags & 0x12) == 0x12:
                            synack_count += 1

                        # ACK without SYN (connection progression)
                        if (flags & 0x10) and not (flags & 0x02):
                            rev = (pkt[IP].dst, dport, pkt[IP].src, sport)
                            if rev in syn_flows:
                                syn_flows.discard(rev)

                    flows.add((pkt[IP].src, sport, pkt[IP].dst, dport, proto))

                # Important: stop_filter is evaluated only on packet arrival.
                # We rely on timeout=5 to end each window even when idle.

                sniff(
                    iface="Ethernet 2",
                    filter=f"host {target_ip}",
                    prn=on_pkt,
                    store=False,
                    timeout=5,  # <-- one 5-second window
                    stop_filter=lambda _: stop_evt.is_set(),
                )

                if stop_evt.is_set():
                    break  # do not emit a partial overlapping window

                window_secs = 5.0
                avg_rate_bytes_ps = (total_bytes / window_secs) if window_secs else 0.0
                avg_pkts_ps = (total_pkts / window_secs) if window_secs else 0.0
                total = total_pkts if total_pkts else 1

                metrics: Metrics = {
                    "bytes_ps": float(avg_rate_bytes_ps),
                    "pkts_ps": float(avg_pkts_ps),
                    "tcp_fraction": float(tcp_cnt / total) if total_pkts else 0.0,
                    "mean_pkt_size": float(sum(pkt_sizes) / len(pkt_sizes)) if pkt_sizes else 0.0,
                    "tiny_pkt_fraction": float(sizes_tiny / total) if total_pkts else 0.0,
                    "syn_rate": float(syn_count / window_secs),
                    "syn_ack_ratio": float((synack_count / syn_count) if syn_count else 0.0),
                    "half_open_conn_count": int(len(syn_flows)),
                    "avg_bytes_per_flow": float((total_bytes / len(flows)) if len(flows) else 0.0),
                    "new_conn_rate": float(len(new_conn_flows) / window_secs),
                    "peak_to_avg_rate": float(
                        (max(bytes_per_sec) / avg_rate_bytes_ps) if avg_rate_bytes_ps > 0 else 0.0
                    ),
                }

                with STORE_LOCK:
                    STORE.setdefault(target_ip, []).append(metrics)
        finally:
            # Cleanup registration no matter how we exit
            with CAPTURE_LOCK:
                CAPTURE_STOP.pop(target_ip, None)
                CAPTURE_THREADS.pop(target_ip, None)
