"""Deterministic synthetic traffic generator.

Fabricates one labelled pcap directly on disk (it never touches a network) plus a matching
offline-intel bundle, so every teammate gets the identical, reproducible demo. Large uploads
are written header-only with a spoofed IP total-length field, so byte counters stay realistic
while the file stays small.
"""

from __future__ import annotations

import random
import socket
import struct
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import dpkt

from enclave.core.constants import PROTO_TCP, PROTO_UDP
from enclave.ingest.parsers.tls import ja3, parse_client_hello
from enclave.intel import write_manifest

SEED = 20260917
DEMO_JA4_BAD = "t12i4713h1_a1b2c3d4e5f6_112233445566"
DGA_TLD = ".ryuk"
TUNNEL_DOMAIN = "qx-sync.test"
CONSONANTS = "bcdfghjklmnpqrstvwxz"
VOWELS = "aeiou"
CHROME_CIPHERS = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014]
CHROME_EXTS = [0x0000, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0010, 0x000D, 0x002B, 0x002D, 0x0033]


@dataclass
class Host:
    ip: str
    mac: bytes


def _mac(n: int) -> bytes:
    return b"\x02\x00" + struct.pack("!I", n)


def _rand_ip(rng: random.Random) -> str:
    return f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


class PcapWriter:
    """Buffers records and writes them in timestamp order, as a real capture would be.

    Scenarios are generated in convenient chunks whose timestamps overlap; sorting on
    close produces a monotonic capture so streaming windows never see out-of-order events.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._records: list[tuple[float, int, bytes, int]] = []
        self._seq = 0

    def write(self, ts: float, frame: bytes, wire_len: int | None = None) -> None:
        wire = wire_len if wire_len is not None else len(frame)
        self._records.append((ts, self._seq, frame, wire))
        self._seq += 1

    def close(self) -> None:
        self._records.sort(key=lambda r: (r[0], r[1]))  # stable within equal timestamps
        with self.path.open("wb") as fh:
            fh.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))  # DLT_EN10MB
            for ts, _seq, frame, wire in self._records:
                sec, usec = int(ts), int((ts - int(ts)) * 1_000_000)
                fh.write(struct.pack("!IIII", sec, usec, len(frame), wire))
                fh.write(frame)


def eth(src: bytes, dst: bytes, ip: dpkt.ip.IP) -> bytes:
    return bytes(dpkt.ethernet.Ethernet(src=src, dst=dst, type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


def _ip(src: str, dst: str, proto: int, ttl: int, l4: object, total_len: int | None = None) -> dpkt.ip.IP:
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=proto, ttl=ttl, data=l4)
    packed = bytearray(bytes(ip))
    if total_len is not None:
        struct.pack_into("!H", packed, 2, total_len)  # spoof IP total length for header-only volume
    return dpkt.ip.IP(bytes(packed))


class Scenario:
    def __init__(self, writer: PcapWriter) -> None:
        self.w = writer
        self.rng = random.Random(SEED)
        self.macs: dict[str, bytes] = {}
        self.t0 = 1_789_000_000.0

    def mac(self, ip: str) -> bytes:
        return self.macs.setdefault(ip, _mac(len(self.macs) + 1))

    def tcp(self, ts: float, src: str, dst: str, sp: int, dp: int, flags: int, payload: bytes = b"",
            ttl: int = 64, total_len: int | None = None) -> None:
        seg = dpkt.tcp.TCP(sport=sp, dport=dp, flags=flags, seq=self.rng.getrandbits(32), data=payload)
        ip = _ip(src, dst, PROTO_TCP, ttl, seg, total_len)
        self.w.write(ts, eth(self.mac(src), self.mac(dst), ip), wire_len=total_len)

    def udp(self, ts: float, src: str, dst: str, sp: int, dp: int, payload: bytes, ttl: int = 64,
            total_len: int | None = None) -> None:
        seg = dpkt.udp.UDP(sport=sp, dport=dp, data=payload)
        seg.ulen = len(seg)
        ip = _ip(src, dst, PROTO_UDP, ttl, seg, total_len)
        self.w.write(ts, eth(self.mac(src), self.mac(dst), ip), wire_len=total_len)

    def handshake(self, ts: float, src: str, dst: str, sp: int, dp: int = 443, ttl: int = 64) -> float:
        self.tcp(ts, src, dst, sp, dp, dpkt.tcp.TH_SYN, ttl=ttl)
        self.tcp(ts + 0.01, dst, src, dp, sp, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, ttl=ttl)
        self.tcp(ts + 0.02, src, dst, sp, dp, dpkt.tcp.TH_ACK, ttl=ttl)
        return ts + 0.03

    def client_hello(self, ja4_extra: bool = False, sni: str | None = "www.example.test") -> bytes:
        ciphers = CHROME_CIPHERS + ([0x00FF] if ja4_extra else [])
        body = bytearray()
        body += struct.pack("!H", 0x0303) + self.rng.randbytes(32) + b"\x00"
        body += struct.pack("!H", len(ciphers) * 2) + b"".join(struct.pack("!H", c) for c in ciphers)
        body += b"\x01\x00"
        exts = bytearray()
        if sni is not None:
            name = sni.encode()
            server_name = struct.pack("!BH", 0, len(name)) + name
            sni_ext = struct.pack("!H", len(server_name)) + server_name
            exts += struct.pack("!HH", 0x0000, len(sni_ext)) + sni_ext
        for ext in (0x000A, 0x000B, 0x000D, 0x002B):
            exts += struct.pack("!HH", ext, 2) + b"\x00\x00"
        body += struct.pack("!H", len(exts)) + exts
        handshake = struct.pack("!B", 1) + struct.pack("!I", len(body))[1:] + bytes(body)
        record = struct.pack("!BHH", 22, 0x0301, len(handshake)) + handshake
        return record

    # --- benign background -------------------------------------------------------------------
    def benign(self, span: float) -> None:
        clients = ["10.30.1.10", "10.30.1.11", "10.30.1.12", "10.30.2.41", "10.30.5.23"]
        servers = ["93.184.216.34", "198.51.100.10", "203.0.113.200"]
        t = 0.0
        while t < span:
            src = self.rng.choice(clients)
            dst = self.rng.choice(servers)
            sp = self.rng.randint(1024, 65000)
            after = self.handshake(self.t0 + t, src, dst, sp)
            self.tcp(after, src, dst, sp, 443, dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, self.client_hello())
            for _ in range(self.rng.randint(2, 5)):
                after += 0.01
                self.tcp(after, dst, src, 443, sp, dpkt.tcp.TH_ACK, self.rng.randbytes(200), total_len=1400)
            self.tcp(after + 0.05, src, dst, sp, 443, dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK)
            self.tcp(after + 0.06, dst, src, 443, sp, dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK)
            # a normal DNS lookup that resolves
            q = dpkt.dns.DNS(id=self.rng.getrandbits(16), qd=[dpkt.dns.DNS.Q(name="cdn.example.test", type=1, cls=1)])
            self.udp(self.t0 + t + 0.1, src, "10.10.0.8", sp, 53, bytes(q))
            resp = dpkt.dns.DNS(bytes(q))
            resp.qr = dpkt.dns.DNS_R
            resp.rcode = 0
            self.udp(self.t0 + t + 0.12, "10.10.0.8", src, 53, sp, bytes(resp))
            t += self.rng.uniform(0.15, 0.5)

    # --- attacks -----------------------------------------------------------------------------
    def scan(self, at: float, src: str = "10.20.4.9", dst: str = "10.10.1.15") -> None:
        for i, port in enumerate(range(1, 1400)):
            self.tcp(at + i * 0.002, src, dst, 40000 + i, port, dpkt.tcp.TH_SYN, ttl=52)

    def modbus_sweep(self, at: float, src: str = "10.30.5.23") -> None:
        for i in range(240):
            self.tcp(at + i * 0.01, src, f"10.40.0.{i % 254 + 1}", 41000 + i, 502, dpkt.tcp.TH_SYN, ttl=60)

    def dga(self, at: float, src: str = "10.30.2.41") -> None:
        alphabet = CONSONANTS + VOWELS + "0123456789"
        for i in range(60):
            label = "".join(self.rng.choice(alphabet) for _ in range(self.rng.randint(15, 24)))
            name = label + DGA_TLD
            q = dpkt.dns.DNS(id=self.rng.getrandbits(16), qd=[dpkt.dns.DNS.Q(name=name, type=1, cls=1)])
            self.udp(at + i * 0.05, src, "10.10.0.8", 50000 + i, 53, bytes(q))
            resp = dpkt.dns.DNS(bytes(q))
            resp.qr = dpkt.dns.DNS_R
            resp.rcode = dpkt.dns.DNS_RCODE_NXDOMAIN
            self.udp(at + i * 0.05 + 0.01, "10.10.0.8", src, 53, 50000 + i, bytes(resp))

    def tunnel(self, at: float, src: str = "10.30.7.12") -> None:
        for i in range(160):
            chunk = "".join(self.rng.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(50))
            name = f"{chunk}.{TUNNEL_DOMAIN}"
            q = dpkt.dns.DNS(id=self.rng.getrandbits(16), qd=[dpkt.dns.DNS.Q(name=name, type=16, cls=1)])
            self.udp(at + i * 0.03, src, "10.10.0.8", 51000, 53, bytes(q))

    def beacon(self, at: float, src: str = "10.30.2.41", dst: str = "203.0.113.66") -> None:
        for i in range(12):
            t = at + i * 15 + self.rng.uniform(-1.1, 1.1)
            sp = 40000 + i
            after = self.handshake(t, src, dst, sp)
            self.tcp(after, src, dst, sp, 443, dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK,
                     self.client_hello(sni="update.cdn.test"), total_len=1240)
            self.tcp(after + 0.05, dst, src, 443, sp, dpkt.tcp.TH_ACK, total_len=1200)
            self.tcp(after + 0.1, src, dst, sp, 443, dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK)

    def syn_flood(self, at: float, dst: str = "10.10.0.5", duration: float = 6.0) -> None:
        n = 12000
        for i in range(n):
            src = _rand_ip(self.rng)
            self.tcp(at + i / n * duration, src, dst, self.rng.randint(1024, 65535), 443,
                     dpkt.tcp.TH_SYN, ttl=self.rng.choice([44, 52, 118, 240]))

    def dns_amplification(self, at: float, dst: str = "10.10.0.8", duration: float = 5.0) -> None:
        n = 4000
        payload = self.rng.randbytes(200)
        for i in range(n):
            reflector = _rand_ip(self.rng).rsplit(".", 1)[0] + ".53"
            self.udp(at + i / n * duration, reflector, dst, 53, 40000 + (i % 1000), payload, total_len=3800)

    def malicious_tls(self, at: float, src: str = "10.30.5.23", dst: str = "198.51.100.77") -> None:
        sp = 44444
        after = self.handshake(at, src, dst, sp)
        # a ClientHello with an extra cipher so its JA3/JA4 differ from the benign fleet, no SNI
        hello = self.client_hello(ja4_extra=True, sni=None)
        self.tcp(after, src, dst, sp, 443, dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, hello, total_len=600)
        for i in range(6):
            self.tcp(after + 0.05 + i * 0.03, dst, src, 443, sp, dpkt.tcp.TH_ACK, total_len=1100)

    def exfil(self, at: float, src: str = "10.30.2.41", dst: str = "203.0.113.50") -> None:
        sp = 55555
        after = self.handshake(at, src, dst, sp)
        self.tcp(after, src, dst, sp, 443, dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, self.client_hello(sni=None),
                 total_len=600)
        for i in range(1000):  # 1000 x 64 KB header-only segments = ~61 MiB, over the 50 MiB threshold
            self.tcp(after + 0.1 + i * 0.01, src, dst, sp, 443, dpkt.tcp.TH_ACK,
                     self.rng.randbytes(60), total_len=64000)
            if i % 20 == 0:
                self.tcp(after + 0.101 + i * 0.01, dst, src, 443, sp, dpkt.tcp.TH_ACK, total_len=52)


def _bad_ja3(scenario: Scenario) -> str:
    return ja3(parse_client_hello(scenario.client_hello(ja4_extra=True, sni=None)))


def generate(pcap_path: Path, intel_dir: Path | None = None) -> dict[str, object]:
    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    writer = PcapWriter(pcap_path)
    sc = Scenario(writer)
    sc.benign(200.0)
    sc.scan(sc.t0 + 20)
    sc.dga(sc.t0 + 35)
    sc.malicious_tls(sc.t0 + 55)
    sc.syn_flood(sc.t0 + 70)
    sc.dns_amplification(sc.t0 + 95)
    sc.tunnel(sc.t0 + 120)
    sc.modbus_sweep(sc.t0 + 150)
    sc.beacon(sc.t0 + 5)              # spans the whole capture (12 x 60 s)
    sc.exfil(sc.t0 + 175)
    bad_ja3 = _bad_ja3(sc)
    writer.close()

    if intel_dir is not None:
        intel_dir.mkdir(parents=True, exist_ok=True)
        (intel_dir / "ja3_blocklist.txt").write_text(f"# demo blocklist\n{bad_ja3}\n", encoding="utf-8")
        (intel_dir / "ja4_blocklist.txt").write_text(f"# demo blocklist\n{DEMO_JA4_BAD}\n", encoding="utf-8")
        (intel_dir / "domain_blocklist.txt").write_text(f"# demo blocklist\n{TUNNEL_DOMAIN}\n", encoding="utf-8")
        write_manifest(intel_dir)
    return {"pcap": str(pcap_path), "bad_ja3": bad_ja3, "labels": [
        "recon_scan", "dga", "encrypted_malware", "ddos", "dns_tunnel", "c2_beacon", "exfiltration", "campaign",
    ]}


# One capture per threat: the same benign background plus a single attack, so each detector can be
# shown (and tested) in isolation. Start times give the baselining detectors (DDoS rate, exfil volume,
# TLS fingerprint rarity) enough normal traffic first; "benign_only" is the no-false-alarm control.
BACKGROUND_SPAN_S = 200.0
THREAT_SCENARIOS: dict[str, tuple[str, Callable[[Scenario], None]]] = {
    "benign_only": ("normal web and DNS traffic only - expect no alerts", lambda sc: None),
    "ddos_syn_flood": ("spoofed-source TCP SYN flood", lambda sc: sc.syn_flood(sc.t0 + 70)),
    "ddos_udp_amplification": ("DNS reflection / amplification flood", lambda sc: sc.dns_amplification(sc.t0 + 95)),
    "c2_beacon": ("C2 check-ins every ~15 s to one destination", lambda sc: sc.beacon(sc.t0 + 5)),
    "dga_domains": ("burst of algorithmically generated, non-existent domains", lambda sc: sc.dga(sc.t0 + 35)),
    "dns_tunnel": ("long encoded subdomains in TXT queries", lambda sc: sc.tunnel(sc.t0 + 120)),
    "encrypted_malware": ("TLS session with a known-bad JA3/JA4 fingerprint and no SNI",
                          lambda sc: sc.malicious_tls(sc.t0 + 120)),
    "recon_port_scan": ("vertical TCP port scan of one host", lambda sc: sc.scan(sc.t0 + 20)),
    "recon_host_sweep": ("horizontal sweep of 240 hosts on Modbus port 502", lambda sc: sc.modbus_sweep(sc.t0 + 150)),
    "exfiltration": ("~61 MiB bulk upload to a new external destination", lambda sc: sc.exfil(sc.t0 + 175)),
}


def generate_threat(pcap_path: Path, threat: str) -> dict[str, object]:
    """Write one labelled capture containing benign background plus a single threat scenario."""
    if threat not in THREAT_SCENARIOS:
        raise ValueError(f"unknown threat {threat!r}; choose from {', '.join(THREAT_SCENARIOS)}")
    description, attack = THREAT_SCENARIOS[threat]
    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    writer = PcapWriter(pcap_path)
    sc = Scenario(writer)
    sc.benign(BACKGROUND_SPAN_S)
    attack(sc)
    writer.close()
    return {"pcap": str(pcap_path), "threat": threat, "description": description}
