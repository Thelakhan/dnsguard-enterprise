import math
from collections import Counter

class DNSFeatureExtractor:
    @staticmethod
    def calc_entropy(text):
        if not text: return 0.0
        freq = Counter(text)
        length = len(text)
        return -sum((count/length) * math.log2(count/length) for count in freq.values())

    @classmethod
    def extract_features(cls, query, qtype, source_ip, timestamp, is_response=False, rcode=None):
        clean_query = str(query).lower().strip('.')
        parts = clean_query.split('.')
        subdomain = ".".join(parts[:-2]) if len(parts) > 2 else clean_query
        
        subdomain_length = len(subdomain)
        labels = parts[:-2] if len(parts) > 2 else [clean_query]
        max_label_entropy = max([cls.calc_entropy(lbl) for lbl in labels] + [0.0])
        subdomain_count = len(labels)
        
        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "query": clean_query,
            "subdomain": subdomain,
            "qtype": qtype,
            "is_response": is_response,
            "rcode": rcode,
            "subdomain_length": subdomain_length,
            "max_label_entropy": round(max_label_entropy, 2),
            "subdomain_count": subdomain_count,
            "is_txt": qtype == 'TXT'
        }