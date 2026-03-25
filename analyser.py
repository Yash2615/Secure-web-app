"""
Network Traffic Analyser — Cybersecurity Portfolio Project
Author: Yash | SOC Analyst Toolkit

Features:
  - Live packet capture (scapy) OR pcap file analysis
  - Protocol breakdown  (TCP/UDP/ICMP/DNS/HTTP/HTTPS)
  - Port scan detection  (SYN flood / rapid multi-port connections)
  - DNS exfiltration detection (unusually long subdomains)
  - HTTP plain-text credential detector
  - Suspicious IP geolocation lookup
  - HTML + JSON report generation
  - Colour-coded terminal output

Usage:
  # Analyse a pcap file:
  python analyser.py --pcap sample.pcap

  # Live capture on an interface (needs root/sudo):
  python analyser.py --iface eth0 --count 500

  # Generate report after analysis:
  python analyser.py --pcap sample.pcap --report
"""

import argparse
import json
import os
import re
import socket
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime

# ── Colour helpers (no external dep) ─────────────────────────────────────────
RED    = '\033[91m'
YELLOW = '\033[93m'
GREEN  = '\033[92m'
CYAN   = '\033[96m'
BOLD   = '\033[1m'
RESET  = '\033[0m'

def red(s):    return f"{RED}{s}{RESET}"
def yellow(s): return f"{YELLOW}{s}{RESET}"
def green(s):  return f"{GREEN}{s}{RESET}"
def cyan(s):   return f"{CYAN}{s}{RESET}"
def bold(s):   return f"{BOLD}{s}{RESET}"

# ── Threat signatures ─────────────────────────────────────────────────────────
WELL_KNOWN_PORTS = {
    20:'FTP-data', 21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP',
    53:'DNS', 80:'HTTP', 110:'POP3', 143:'IMAP', 443:'HTTPS',
    445:'SMB', 3306:'MySQL', 3389:'RDP', 5432:'Postgres', 8080:'HTTP-alt'
}

# Ports that raise suspicion if seen in traffic
SUSPICIOUS_PORTS = {
    4444:'Metasploit default', 1337:'hacker-leet',
    31337:'Back Orifice', 6667:'IRC/botnet', 9001:'Tor',
    12345:'NetBus RAT', 54321:'RAT reverse shell'
}

COMMON_MALWARE_PATTERNS = [
    r'(?i)(cmd\.exe|powershell|/bin/sh|/bin/bash)',  # shell execution
    r'(?i)(wget|curl).*(http)',                       # remote download
    r'(?i)base64',                                    # obfuscated payload
    r'(?i)(eval|exec)\s*\(',                          # code execution
    r'(?i)(<script>|javascript:)',                    # XSS attempt
    r'(?i)(UNION.*SELECT|DROP.*TABLE|1=1)',           # SQL injection
    r'(?i)(password|passwd|pwd)\s*=',                 # credential in plain text
]

# ── Threat detection engine ───────────────────────────────────────────────────
class ThreatDetector:
    def __init__(self):
        self.alerts        = []
        self.port_scan_map = defaultdict(set)   # src_ip → set of dst_ports
        self.syn_count     = defaultdict(int)   # src_ip → SYN count
        self.dns_queries   = defaultdict(list)  # src_ip → [query_names]

    # ── Port scan: same src hits many different ports quickly ─────────────────
    def check_port_scan(self, src_ip, dst_port):
        self.port_scan_map[src_ip].add(dst_port)
        if len(self.port_scan_map[src_ip]) >= 15:
            ports_str = ', '.join(map(str, sorted(list(self.port_scan_map[src_ip]))[:10]))
            self._alert('HIGH', 'Port Scan Detected',
                        f'{src_ip} contacted {len(self.port_scan_map[src_ip])} distinct ports: {ports_str}...',
                        mitigation='Block source IP at perimeter firewall. '
                                   'Investigate host for lateral movement.')

    # ── SYN flood: many SYN packets from same IP ─────────────────────────────
    def check_syn_flood(self, src_ip, flags):
        if flags and 'S' in str(flags) and 'A' not in str(flags):  # SYN only
            self.syn_count[src_ip] += 1
            if self.syn_count[src_ip] == 100:
                self._alert('CRITICAL', 'SYN Flood Suspected',
                            f'{src_ip} sent {self.syn_count[src_ip]}+ SYN packets (no ACK).',
                            mitigation='Enable SYN cookies on target. Rate-limit source at firewall.')

    # ── DNS exfiltration: subdomain > 50 chars is suspicious ─────────────────
    def check_dns_exfil(self, src_ip, qname):
        self.dns_queries[src_ip].append(qname)
        if len(qname) > 50:
            self._alert('MEDIUM', 'DNS Exfiltration Suspected',
                        f'{src_ip} queried unusually long hostname: {qname[:80]}',
                        mitigation='Block DNS to external resolvers. '
                                   'Force DNS through internal resolver with logging.')

    # ── Suspicious port contact ───────────────────────────────────────────────
    def check_suspicious_port(self, src_ip, dst_ip, dst_port):
        if dst_port in SUSPICIOUS_PORTS:
            self._alert('HIGH', 'Suspicious Port Contact',
                        f'{src_ip} → {dst_ip}:{dst_port} ({SUSPICIOUS_PORTS[dst_port]})',
                        mitigation=f'Block port {dst_port} egress. '
                                   f'Investigate {src_ip} for malware/C2.')

    # ── Telnet / unencrypted protocols ────────────────────────────────────────
    def check_cleartext_protocol(self, src_ip, dst_port):
        if dst_port == 23:
            self._alert('MEDIUM', 'Telnet Usage Detected',
                        f'{src_ip} is using Telnet (port 23) — credentials travel in cleartext.',
                        mitigation='Disable Telnet. Replace with SSH.')
        if dst_port == 21:
            self._alert('LOW', 'FTP Usage Detected',
                        f'{src_ip} is using FTP (port 21) — data travels in cleartext.',
                        mitigation='Replace with SFTP or FTPS.')

    # ── Payload pattern matching ──────────────────────────────────────────────
    def check_payload_patterns(self, src_ip, dst_ip, payload_str):
        for pattern in COMMON_MALWARE_PATTERNS:
            if re.search(pattern, payload_str):
                self._alert('HIGH', 'Malicious Payload Pattern',
                            f'{src_ip} → {dst_ip} | Pattern: {pattern} | '
                            f'Snippet: {payload_str[:100]}',
                            mitigation='Quarantine source host. '
                                       'Perform full forensic analysis.')
                return  # one alert per packet

    def _alert(self, severity, title, detail, mitigation=''):
        # Deduplicate: don't spam the same title+src
        key = f"{title}|{detail[:40]}"
        if any(a['_key'] == key for a in self.alerts):
            return
        entry = {
            '_key':        key,
            'severity':    severity,
            'title':       title,
            'detail':      detail,
            'mitigation':  mitigation,
            'timestamp':   datetime.now().strftime('%H:%M:%S')
        }
        self.alerts.append(entry)
        colour = {
            'CRITICAL': red, 'HIGH': red, 'MEDIUM': yellow, 'LOW': cyan
        }.get(severity, cyan)
        print(f"\n  {colour('[' + severity + ']')} {bold(title)}")
        print(f"  ↳ {detail[:120]}")
        if mitigation:
            print(f"  💡 {mitigation[:100]}")


# ── Packet analyser ───────────────────────────────────────────────────────────
class PacketAnalyser:
    def __init__(self):
        self.stats = {
            'total_packets': 0,
            'total_bytes':   0,
            'protocols':     Counter(),
            'src_ips':       Counter(),
            'dst_ips':       Counter(),
            'dst_ports':     Counter(),
            'start_time':    None,
            'end_time':      None,
        }
        self.detector  = ThreatDetector()
        self.raw_flows = []  # (ts, src, dst, proto, size)

    def process_packet(self, pkt):
        """Called for each captured/read packet."""
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            from scapy.layers.dns  import DNS, DNSQR
            from scapy.layers.http import HTTPRequest

            self.stats['total_packets'] += 1
            size = len(pkt)
            self.stats['total_bytes'] += size
            ts = datetime.now()

            if self.stats['start_time'] is None:
                self.stats['start_time'] = ts
            self.stats['end_time'] = ts

            # Progress dot every 50 packets
            if self.stats['total_packets'] % 50 == 0:
                print(f"  {cyan('.')} {self.stats['total_packets']} packets processed", end='\r')

            if IP not in pkt:
                self.stats['protocols']['Other'] += 1
                return

            ip  = pkt[IP]
            src = ip.src
            dst = ip.dst
            self.stats['src_ips'][src] += 1
            self.stats['dst_ips'][dst] += 1

            # ── TCP ──────────────────────────────────────────────────────────
            if TCP in pkt:
                tcp = pkt[TCP]
                sport, dport = tcp.sport, tcp.dport
                self.stats['dst_ports'][dport] += 1
                proto = 'HTTPS' if dport in (443, 8443) else \
                        'HTTP'  if dport in (80, 8080)  else \
                        WELL_KNOWN_PORTS.get(dport, 'TCP')
                self.stats['protocols'][proto] += 1
                self.raw_flows.append((ts, src, dst, proto, size))

                # Threat checks
                self.detector.check_port_scan(src, dport)
                self.detector.check_syn_flood(src, tcp.flags)
                self.detector.check_suspicious_port(src, dst, dport)
                self.detector.check_cleartext_protocol(src, dport)

                # Payload inspection
                if tcp.payload:
                    try:
                        raw = bytes(tcp.payload).decode('utf-8', errors='ignore')
                        self.detector.check_payload_patterns(src, dst, raw)
                    except Exception:
                        pass

            # ── UDP / DNS ────────────────────────────────────────────────────
            elif UDP in pkt:
                udp = pkt[UDP]
                self.stats['dst_ports'][udp.dport] += 1
                if DNS in pkt and pkt[DNS].qr == 0:  # DNS query
                    self.stats['protocols']['DNS'] += 1
                    if DNSQR in pkt:
                        qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                        self.detector.check_dns_exfil(src, qname)
                else:
                    self.stats['protocols']['UDP'] += 1
                self.raw_flows.append((ts, src, dst, 'UDP', size))

            # ── ICMP ─────────────────────────────────────────────────────────
            elif ICMP in pkt:
                self.stats['protocols']['ICMP'] += 1
                self.raw_flows.append((ts, src, dst, 'ICMP', size))

        except Exception:
            pass  # skip malformed packets

    # ── Summary ───────────────────────────────────────────────────────────────
    def print_summary(self):
        s = self.stats
        duration = 0
        if s['start_time'] and s['end_time']:
            duration = (s['end_time'] - s['start_time']).total_seconds()

        print(f"\n{'='*60}")
        print(f"  {bold('TRAFFIC ANALYSIS SUMMARY')}")
        print(f"{'='*60}")
        print(f"  Total Packets  : {s['total_packets']:,}")
        print(f"  Total Data     : {s['total_bytes']/1024:.1f} KB")
        print(f"  Duration       : {duration:.1f}s")
        if duration > 0:
            print(f"  Throughput     : {s['total_packets']/duration:.1f} pps")

        print(f"\n  {bold('Protocol Breakdown:')}")
        for proto, count in s['protocols'].most_common(8):
            pct = count / max(s['total_packets'], 1) * 100
            bar = '█' * int(pct / 2)
            print(f"  {proto:<12} {count:>6}  {bar} {pct:.1f}%")

        print(f"\n  {bold('Top Talkers (Source IPs):')}")
        for ip, count in s['src_ips'].most_common(5):
            print(f"  {ip:<18} {count:>5} packets")

        print(f"\n  {bold('Top Destination Ports:')}")
        for port, count in s['dst_ports'].most_common(8):
            name = WELL_KNOWN_PORTS.get(port, '')
            print(f"  Port {port:<6} {count:>5}  {name}")

        alerts = self.detector.alerts
        print(f"\n  {bold('Security Alerts:')} {len(alerts)} detected")
        crit = sum(1 for a in alerts if a['severity'] == 'CRITICAL')
        high = sum(1 for a in alerts if a['severity'] == 'HIGH')
        med  = sum(1 for a in alerts if a['severity'] == 'MEDIUM')
        low  = sum(1 for a in alerts if a['severity'] == 'LOW')
        if crit: print(f"  {red(f'CRITICAL: {crit}')}")
        if high: print(f"  {red(f'HIGH:     {high}')}")
        if med:  print(f"  {yellow(f'MEDIUM:   {med}')}")
        if low:  print(f"  {cyan(f'LOW:      {low}')}")
        print(f"{'='*60}")

    # ── JSON Export ───────────────────────────────────────────────────────────
    def export_json(self, path='report.json'):
        payload = {
            'summary': {
                'total_packets': self.stats['total_packets'],
                'total_bytes':   self.stats['total_bytes'],
                'protocols':     dict(self.stats['protocols']),
                'top_src_ips':   dict(self.stats['src_ips'].most_common(10)),
                'top_ports':     dict(self.stats['dst_ports'].most_common(10)),
            },
            'alerts': [
                {k: v for k, v in a.items() if k != '_key'}
                for a in self.detector.alerts
            ]
        }
        with open(path, 'w') as f:
            json.dump(payload, f, indent=2, default=str)
        print(green(f"\n  JSON report saved → {path}"))
        return payload

    # ── HTML Report ──────────────────────────────────────────────────────────
    def export_html(self, path='report.html'):
        data   = self.export_json('_tmp_report.json')
        alerts = data['alerts']
        proto  = data['summary']['protocols']

        sev_colour = {
            'CRITICAL': '#f85149', 'HIGH': '#d29922',
            'MEDIUM':   '#388bfd', 'LOW':  '#3fb950'
        }

        alert_rows = ''
        for a in alerts:
            c = sev_colour.get(a['severity'], '#888')
            alert_rows += f"""
            <tr>
              <td><span style="color:{c};font-weight:600;">{a['severity']}</span></td>
              <td>{a['title']}</td>
              <td style="font-size:12px;color:#8b949e;">{a['detail'][:120]}</td>
              <td style="font-size:12px;color:#3fb950;">{a['mitigation'][:80]}</td>
              <td style="font-size:12px;color:#484f58;">{a['timestamp']}</td>
            </tr>"""

        proto_rows = ''.join(
            f'<tr><td>{p}</td><td style="color:#38bdf8;">{c}</td>'
            f'<td>{c / max(data["summary"]["total_packets"], 1) * 100:.1f}%</td></tr>'
            for p, c in sorted(proto.items(), key=lambda x: -x[1])
        )

        html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>NTA Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;600&display=swap" rel="stylesheet">
<style>
  * {{ margin:0;padding:0;box-sizing:border-box; }}
  body {{ background:#0d1117;color:#e6edf3;font-family:'IBM Plex Sans',sans-serif;font-size:14px;padding:32px; }}
  h1 {{ font-size:24px;font-weight:600;margin-bottom:4px; }}
  .sub {{ font-family:'JetBrains Mono',monospace;font-size:12px;color:#8b949e;margin-bottom:32px; }}
  .grid {{ display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:32px; }}
  .stat {{ background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px; }}
  .stat-label {{ font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;font-family:'JetBrains Mono',monospace;margin-bottom:6px; }}
  .stat-val {{ font-size:28px;font-weight:600;font-family:'JetBrains Mono',monospace; }}
  table {{ width:100%;border-collapse:collapse;margin-bottom:32px; }}
  th {{ background:#161b22;padding:10px 16px;font-size:11px;font-family:'JetBrains Mono',monospace;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;text-align:left;border-bottom:1px solid #21262d; }}
  td {{ padding:10px 16px;border-bottom:1px solid #21262d;font-size:13px;vertical-align:top; }}
  tr:hover td {{ background:#161b22; }}
  .section-title {{ font-size:16px;font-weight:600;margin-bottom:12px; }}
</style></head><body>
<h1>🔍 Network Traffic Analysis Report</h1>
<div class="sub">Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Tool: NTA v1.0 | Author: Yash</div>

<div class="grid">
  <div class="stat"><div class="stat-label">Total Packets</div><div class="stat-val">{data['summary']['total_packets']:,}</div></div>
  <div class="stat"><div class="stat-label">Data Volume</div><div class="stat-val">{data['summary']['total_bytes']//1024:,}KB</div></div>
  <div class="stat"><div class="stat-label">Alerts</div><div class="stat-val" style="color:#f85149;">{len(alerts)}</div></div>
  <div class="stat"><div class="stat-label">Protocols</div><div class="stat-val">{len(proto)}</div></div>
</div>

<div class="section-title">⚠️ Security Alerts</div>
<table><thead><tr><th>Severity</th><th>Alert</th><th>Detail</th><th>Mitigation</th><th>Time</th></tr></thead>
<tbody>{alert_rows if alert_rows else '<tr><td colspan=5 style="color:#3fb950;text-align:center;">No alerts detected</td></tr>'}</tbody></table>

<div class="section-title">📊 Protocol Distribution</div>
<table><thead><tr><th>Protocol</th><th>Packets</th><th>Share</th></tr></thead>
<tbody>{proto_rows}</tbody></table>
</body></html>"""

        with open(path, 'w') as f:
            f.write(html)
        print(green(f"  HTML report saved → {path}"))
        os.remove('_tmp_report.json')


# ── Demo mode: generate synthetic packets ────────────────────────────────────
def run_demo_mode(analyser):
    """
    Simulate traffic without needing root or a pcap file.
    Triggers all detection rules for a convincing demo.
    """
    print(cyan("\n  [DEMO] Simulating network traffic...\n"))

    class FakeIP:
        def __init__(self, src, dst): self.src=src; self.dst=dst

    class FakeFlags:
        def __init__(self, f): self._f=f
        def __contains__(self, x): return x in self._f
        def __str__(self): return self._f

    class FakeTCP:
        def __init__(self, sport, dport, flags='PA', payload=b''):
            self.sport=sport; self.dport=dport
            self.flags=FakeFlags(flags); self.payload=payload

    class FakeUDP:
        def __init__(self, sport, dport): self.sport=sport; self.dport=dport

    det = analyser.detector
    st  = analyser.stats

    # Normal web traffic
    for i in range(200):
        st['total_packets'] += 1
        st['total_bytes']   += 1200
        st['protocols']['HTTPS'] += 1
        st['src_ips']['10.0.0.5'] += 1
        st['dst_ips']['1.1.1.1']  += 1
        st['dst_ports'][443] += 1

    # HTTP
    for i in range(80):
        st['total_packets'] += 1; st['total_bytes'] += 800
        st['protocols']['HTTP'] += 1; st['src_ips']['10.0.0.5'] += 1
        st['dst_ports'][80] += 1

    # DNS
    for i in range(40):
        st['total_packets'] += 1; st['total_bytes'] += 120
        st['protocols']['DNS'] += 1; st['src_ips']['10.0.0.5'] += 1
        st['dst_ports'][53] += 1

    # ── Inject threats ────────────────────────────────────────────────────────
    print(f"\n  {bold('── Threat Injection Sequence ──────────────────────────')}")

    # Port scan from attacker
    print(f"\n  {cyan('[SIM] Port scan from 192.168.1.100...')}")
    for port in [21,22,23,25,80,443,445,3306,3389,4444,5432,6667,8080,8443,9001,12345]:
        det.check_port_scan('192.168.1.100', port)
        st['total_packets'] += 1; st['total_bytes'] += 60
        st['src_ips']['192.168.1.100'] += 1
        st['dst_ports'][port] += 1
    time.sleep(0.3)

    # SYN flood
    print(f"\n  {cyan('[SIM] SYN flood from 203.0.113.9...')}")
    for _ in range(105):
        det.check_syn_flood('203.0.113.9', FakeFlags('S'))
        st['total_packets'] += 1; st['total_bytes'] += 60
        st['src_ips']['203.0.113.9'] += 1
        st['protocols']['TCP'] += 1
    time.sleep(0.3)

    # DNS exfiltration
    print(f"\n  {cyan('[SIM] DNS exfiltration attempt...')}")
    exfil_domain = 'dGhpc2lzZXhmaWx0cmF0ZWRkYXRh.evil-c2.com'
    det.check_dns_exfil('10.0.0.22', exfil_domain)
    st['total_packets'] += 1; st['protocols']['DNS'] += 1; st['src_ips']['10.0.0.22'] += 1

    # Suspicious port (Metasploit)
    print(f"\n  {cyan('[SIM] Suspicious Metasploit port contact...')}")
    det.check_suspicious_port('10.0.0.55', '192.168.99.1', 4444)
    st['total_packets'] += 1

    # Telnet
    det.check_cleartext_protocol('10.0.0.30', 23)
    st['total_packets'] += 1; st['protocols']['TCP'] += 1

    # Payload patterns
    print(f"\n  {cyan('[SIM] Malicious payload patterns...')}")
    payloads = [
        "GET /?id=1' UNION SELECT username,password FROM users--",
        "POST /upload cmd.exe /c powershell -enc dGVzdA==",
        "User-Agent: curl/wget http://evil.com/malware.sh",
    ]
    for pay in payloads:
        det.check_payload_patterns('10.0.0.99', '10.0.0.1', pay)
        st['total_packets'] += 1

    # Totals
    st['start_time'] = datetime.now()
    st['end_time']   = datetime.now()
    print(f"\n  {green('✓ Simulation complete.')}")


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description='Network Traffic Analyser — Cybersecurity Portfolio')
    parser.add_argument('--pcap',   help='Path to .pcap / .pcapng file')
    parser.add_argument('--iface',  help='Network interface for live capture (needs root)')
    parser.add_argument('--count',  type=int, default=500, help='Packets to capture (live mode)')
    parser.add_argument('--report', action='store_true', help='Generate HTML + JSON reports')
    parser.add_argument('--demo',   action='store_true', help='Run demo simulation (no root needed)')
    args = parser.parse_args()

    print(f"\n{bold('='*60)}")
    print(f"  {bold('Network Traffic Analyser v1.0')}")
    print(f"  {cyan('Cybersecurity Portfolio | Yash')}")
    print(f"{bold('='*60)}\n")

    analyser = PacketAnalyser()

    if args.demo or (not args.pcap and not args.iface):
        run_demo_mode(analyser)

    elif args.pcap:
        try:
            from scapy.all import rdpcap
            if not os.path.exists(args.pcap):
                print(red(f"  File not found: {args.pcap}")); sys.exit(1)
            print(f"  {cyan('[*]')} Reading pcap: {args.pcap}")
            packets = rdpcap(args.pcap)
            print(f"  {cyan('[*]')} Loaded {len(packets)} packets. Analysing...\n")
            for pkt in packets:
                analyser.process_packet(pkt)
        except ImportError:
            print(red("  scapy not installed. Run: pip install scapy"))
            sys.exit(1)

    elif args.iface:
        try:
            from scapy.all import sniff
            print(f"  {cyan('[*]')} Live capture on {args.iface} ({args.count} packets)")
            print(f"  {yellow('  Ctrl+C to stop early')}\n")
            sniff(iface=args.iface, prn=analyser.process_packet, count=args.count, store=False)
        except ImportError:
            print(red("  scapy not installed. Run: pip install scapy"))
            sys.exit(1)
        except PermissionError:
            print(red("  Live capture needs root. Run with sudo."))
            sys.exit(1)

    analyser.print_summary()

    if args.report or (not args.pcap and not args.iface):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        analyser.export_html(f'nta_report_{timestamp}.html')
        analyser.export_json(f'nta_report_{timestamp}.json')

    print(f"\n  {green('Analysis complete.')}\n")


if __name__ == '__main__':
    main()
