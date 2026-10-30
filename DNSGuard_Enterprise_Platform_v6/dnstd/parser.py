import re
import pandas as pd
from scapy.all import rdpcap, DNS, IP, IPv6

QTYPE_MAP = {1: 'A', 2: 'NS', 5: 'CNAME', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 255: 'ANY'}
RCODE_MAP = {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED'}

class LogParser:
    def __init__(self, filepath):
        self.filepath = filepath

    def parse(self):
        if self.filepath.endswith('.csv'): return self._parse_csv()
        elif self.filepath.endswith('.pcap') or self.filepath.endswith('.pcapng'): return self._parse_pcap()
        raise ValueError("Unsupported format.")

    def _parse_pcap(self):
        packets = rdpcap(self.filepath)
        records = []
        for pkt in packets:
            if not pkt.haslayer(DNS): continue
            dns = pkt[DNS]
            src_ip = "Unknown"
            if pkt.haslayer(IP): src_ip = pkt[IP].src
            elif pkt.haslayer(IPv6): src_ip = pkt[IPv6].src
            
            qname = ""
            qtype = "Unknown"
            if hasattr(dns, 'qd') and dns.qd is not None:
                raw_qname = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                # Sanitize non-printable binary characters
                qname = re.sub(r'[^\x20-\x7E]', '', raw_qname)
                qtype = QTYPE_MAP.get(dns.qd.qtype, str(dns.qd.qtype))
            
            if not qname: continue
            
            is_response = dns.qr != 0
            rcode = RCODE_MAP.get(dns.rcode, str(dns.rcode)) if is_response else None

            records.append({
                'timestamp': float(pkt.time), 'source_ip': src_ip, 'query': qname, 
                'qtype': qtype, 'is_response': is_response, 'rcode': rcode
            })
        return records

    def _parse_csv(self):
        df = pd.read_csv(self.filepath)
        records = []
        for _, row in df.iterrows():
            q = str(row.get('query', ''))
            clean_q = re.sub(r'[^\x20-\x7E]', '', q)
            if not clean_q: continue
            records.append({
                'timestamp': float(row.get('timestamp', 0)),
                'source_ip': str(row.get('source_ip', 'Unknown')),
                'query': clean_q,
                'qtype': str(row.get('qtype', 'A')),
                'is_response': bool(row.get('is_response', False)),
                'rcode': str(row.get('rcode', '')) if pd.notna(row.get('rcode', '')) else None
            })
        return records
