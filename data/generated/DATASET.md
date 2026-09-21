# Generated dataset - provenance

Reproduce exactly: `python ml/generate_dataset.py --seed 20260917`. No packets are sent;
each class models the flow-level signature of the tool named in the problem statement.

## flows.csv (flow-feature dataset for the `ml-flow` classifier)

| Class | Rows | Models |
| --- | --- | --- |
| benign | 8,000 | iperf3 bulk transfer, HTTP(S) browsing, DNS lookups, keepalives |
| ddos | 8,000 | hping3 SYN flood, hping3 UDP flood, Slowloris slow-HTTP exhaustion |
| recon_scan | 8,000 | port / host scanning (nmap-style fan-out) |
| c2_beacon | 8,000 | sandboxed C2 emulator: regular beacon check-ins |
| exfiltration | 8,000 | bulk outbound upload with asymmetric byte ratio |

Features (17): duration_s, total_packets, total_bytes, fwd_packets, bwd_packets, fwd_bytes, bwd_bytes, bytes_per_s, packets_per_s, fwd_pkt_len_mean, bwd_pkt_len_mean, down_up_ratio, fwd_bwd_pkt_ratio, syn_flag, rst_flag, is_tcp, is_udp.

## dns.csv (DNS-name dataset for DGA / tunnelling)

| Class | Rows | Models |
| --- | --- | --- |
| benign | 8,000 | pronounceable brand/service names, common TLDs |
| dga | 8,000 | published-style DGA: arithmetic and dictionary algorithms |
| dns_tunnel | 8,000 | iodine / dnscat2 style long high-entropy subdomains, TXT/NULL records |

Features: label_length, label_entropy, digit_ratio, rare_bigram_ratio, dga_score, subdomain_max_label_len, subdomain_entropy, num_labels, qtype, is_txt_or_null (the `query` column is kept for inspection and is not a feature).
