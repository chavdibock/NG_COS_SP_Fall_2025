from typing import  TypedDict


class Metrics(TypedDict):
    bytes_ps: float
    pkts_ps: float
    tcp_fraction: float
    mean_pkt_size: float
    syn_rate: float
    syn_ack_ratio: float
    half_open_conn_count: int
    avg_bytes_per_flow: float
    new_conn_rate: float
    peak_to_avg_rate: float



