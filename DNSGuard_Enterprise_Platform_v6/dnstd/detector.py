import math
from collections import Counter, defaultdict
import datetime
from dnstd.extractor import DNSFeatureExtractor
from dnstd.enrichment import ThreatEnrichment

class DNSTunnelDetector:
    def __init__(self, config):
        self.update_config(config)
        
    def update_config(self, config):
        self.thresholds = config.get('thresholds', {})
        self.allowlist = config.get('allowlist', [])
        
    def analyze(self, raw_records):
        alerts = []
        freq_tracker = defaultdict(int)
        domain_stats = defaultdict(lambda: {'total': 0, 'nxdomain': 0})
        timeline = defaultdict(lambda: {'normal': 0, 'suspicious': 0})
        qtype_counts = Counter()
        severity_counts = Counter({'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0})

        for rec in raw_records:
            query = rec.get('query', '')
            is_response = rec.get('is_response', False)
            ts = rec.get('timestamp', 0)
            src_ip = rec.get('source_ip', 'Unknown')
            qtype = rec.get('qtype', 'A')
            rcode = rec.get('rcode')

            if not query: continue

            try:
                dt = datetime.datetime.fromtimestamp(ts)
            except:
                dt = datetime.datetime.now()
            time_key = dt.strftime('%H:%M')

            if any(query.endswith(a) for a in self.allowlist):
                timeline[time_key]['normal'] += 1
                continue

            if is_response:
                domain_stats[query]['total'] += 1
                if rcode == 'NXDOMAIN': domain_stats[query]['nxdomain'] += 1
                continue

            qtype_counts[qtype] += 1
            features = DNSFeatureExtractor.extract_features(query, qtype, src_ip, ts)
            
            window = int(ts // self.thresholds['frequency']['window_seconds'])
            freq_key = (src_ip, window)
            freq_tracker[freq_key] += 1

            reasons = []
            if freq_tracker[freq_key] > self.thresholds['frequency']['max_queries_per_window']:
                reasons.append(f"High Frequency (>{self.thresholds['frequency']['max_queries_per_window']}/min)")
                
            if features['subdomain_length'] > self.thresholds['subdomain_length']['critical']:
                reasons.append(f"Excessive Length ({features['subdomain_length']})")
            elif features['subdomain_length'] > self.thresholds['subdomain_length']['warning']:
                reasons.append(f"Suspicious Length ({features['subdomain_length']})")
                
            if features['max_label_entropy'] > self.thresholds['entropy']['critical']:
                reasons.append(f"Critical Entropy ({features['max_label_entropy']})")
            elif features['max_label_entropy'] > self.thresholds['entropy']['warning']:
                reasons.append(f"High Entropy ({features['max_label_entropy']})")
                
            if features['is_txt']:
                reasons.append("Suspicious TXT Record Activity")

            if reasons:
                risk_score, severity = ThreatEnrichment.calculate_risk_score(features, reasons)
                
                # Baseline filter: ensure ultra-low risk events don't clutter the UI
                if risk_score >= 10:
                    severity_counts[severity] += 1
                    timeline[time_key]['suspicious'] += 1
                    alerts.append({
                        "timestamp": dt.strftime('%Y-%m-%d %H:%M:%S'),
                        "source_ip": src_ip,
                        "query": query,
                        "qtype": qtype,
                        "entropy": features['max_label_entropy'],
                        "risk_score": risk_score,
                        "severity": severity,
                        "reason": " | ".join(reasons)
                    })
            else:
                timeline[time_key]['normal'] += 1

        # Sort highest risk first
        alerts.sort(key=lambda x: (x['risk_score'], x['timestamp']), reverse=True)
        sorted_times = sorted(timeline.keys())

        return {
            "kpis": {
                "total_analyzed": len(raw_records),
                "alerts_count": len(alerts),
                "top_qtype": qtype_counts.most_common(1)[0][0] if qtype_counts else "N/A",
                "unique_domains": len(domain_stats)
            },
            "timeline": {
                "labels": sorted_times,
                "normal": [timeline[t]['normal'] for t in sorted_times],
                "suspicious": [timeline[t]['suspicious'] for t in sorted_times]
            },
            "qtypes": {
                "labels": list(qtype_counts.keys()),
                "data": list(qtype_counts.values())
            },
            "severities": {
                "labels": ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                "data": [severity_counts['CRITICAL'], severity_counts['HIGH'], severity_counts['MEDIUM'], severity_counts['LOW']]
            },
            # Expanded limit from 150 to 1000 to capture all severity tiers
            "alerts": alerts[:1000]
        }
