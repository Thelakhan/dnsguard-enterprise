class ThreatEnrichment:
    @staticmethod
    def calculate_risk_score(features, reasons, is_blocklisted=False):
        score = 10.0  # Base network baseline
        
        if is_blocklisted:
            return 95.0, "CRITICAL"
            
        # Entropy impact (Up to +35 pts)
        entropy = features.get('max_label_entropy', 0.0)
        if entropy > 4.5:
            score += 35.0
        elif entropy > 3.5:
            score += 20.0
            
        # Length impact (Up to +30 pts)
        length = features.get('subdomain_length', 0)
        if length > 60:
            score += 30.0
        elif length > 45:
            score += 15.0
            
        # Reason count impact (Up to +25 pts)
        score += min(len(reasons) * 12.0, 25.0)
        
        final_score = min(round(score, 1), 100.0)
        
        # Severity mapping
        if final_score >= 75.0:
            severity = "CRITICAL"
        elif final_score >= 50.0:
            severity = "HIGH"
        elif final_score >= 25.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"
            
        return final_score, severity