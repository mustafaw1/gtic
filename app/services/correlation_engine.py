"""
Correlation Engine for combining IOC and CVE results.
This engine calculates confidence scores and priorities based on both IOC and CVE matches.
"""

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """Engine for correlating IOC and CVE results"""
    
    @staticmethod
    def correlate_ioc_and_cve(
        ioc_results: List[Dict[str, Any]],
        cve_results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Correlate IOC and CVE results to calculate confidence and priority.
        
        Args:
            ioc_results: List of IOC match results (IPs, domains, hashes)
            cve_results: List of CVE match results
            
        Returns:
            Dictionary with correlation metadata including confidence, priority, and reason
        """
        ioc_matched = len(ioc_results) > 0
        cve_matched = len(cve_results) > 0
        confidence = 50
        
        if ioc_matched:
            threat_scores = []
            for ioc in ioc_results:
                threat_score = ioc.get("threat_score", 0)
                if threat_score:
                    threat_scores.append(threat_score)
            
            if threat_scores:
                avg_threat_score = sum(threat_scores) / len(threat_scores)
                if avg_threat_score >= 8:
                    confidence += 30
                elif avg_threat_score >= 5:
                    confidence += 20
                else:
                    confidence += 10
        
        if cve_matched:
            cve_scores = []
            severities = []
            
            for cve in cve_results:
                score = cve.get("score", 0.0)
                severity = cve.get("severity", "NONE")
                if score:
                    cve_scores.append(score)
                if severity:
                    severities.append(severity)
            
            if cve_scores:
                max_score = max(cve_scores)
                
                if max_score >= 9.0:
                    confidence += 25
                elif max_score >= 7.0:
                    confidence += 15
                elif max_score >= 4.0:
                    confidence += 10
                else:
                    confidence += 5
        
        confidence = min(100, confidence)
        
        if confidence >= 90:
            priority = "CRITICAL"
        elif confidence >= 70:
            priority = "HIGH"
        elif confidence >= 50:
            priority = "MEDIUM"
        else:
            priority = "LOW"
        
        reason_parts = []
        
        if ioc_matched:
            ioc_types = []
            ioc_values = []
            threat_scores = []
            
            for ioc in ioc_results:
                ioc_type = ioc.get("ioc_type") or (
                    "ip" if ioc.get("ip_address") else
                    "domain" if ioc.get("domain_name") else
                    "hash" if ioc.get("hash_value") else "IOC"
                )
                ioc_value = (
                    ioc.get("ip_address") or
                    ioc.get("domain_name") or
                    ioc.get("hash_value") or
                    "unknown"
                )
                threat_score = ioc.get("threat_score", 0)
                
                ioc_types.append(ioc_type)
                ioc_values.append(ioc_value)
                threat_scores.append(threat_score)
            
            avg_threat = sum(threat_scores) / len(threat_scores) if threat_scores else 0.0
            reason_parts.append(
                f"Malicious {', '.join(set(ioc_types))} detected "
                f"(avg threat_score: {avg_threat:.1f})"
            )
        
        if cve_matched:
            cve_ids = []
            max_severity = "NONE"
            max_score = 0.0
            
            for cve in cve_results:
                cve_id = cve.get("id") or cve.get("cve_id", "unknown")
                severity = cve.get("severity", "NONE")
                score = cve.get("score", 0.0)
                
                cve_ids.append(cve_id)
                if severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
                    if severity_order.get(severity, 0) > severity_order.get(max_severity, 0):
                        max_severity = severity
                if score > max_score:
                    max_score = score
            
            reason_parts.append(
                f"Asset has {max_severity} vulnerability "
                f"(CVE: {', '.join(cve_ids[:3])}{'...' if len(cve_ids) > 3 else ''}, "
                f"max score: {max_score:.1f})"
            )
        
        if not reason_parts:
            reason = "No IOC or CVE matches found"
        else:
            reason = " | ".join(reason_parts)
        
        return {
            "confidence": confidence,
            "priority": priority,
            "reason": reason,
            "ioc_matched": ioc_matched,
            "cve_matched": cve_matched,
            "ioc_count": len(ioc_results),
            "cve_count": len(cve_results)
        }
    
    @staticmethod
    def format_correlation_result(
        ioc_results: List[Dict[str, Any]],
        cve_results: List[Dict[str, Any]],
        correlation_metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Format the complete correlation result.
        
        Args:
            ioc_results: List of IOC match results
            cve_results: List of CVE match results
            correlation_metadata: Correlation metadata from correlate_ioc_and_cve
            
        Returns:
            Formatted correlation result dictionary
        """
        return {
            "ioc_correlation": {
                "matched": correlation_metadata.get("ioc_matched", False),
                "matches": ioc_results,
                "count": correlation_metadata.get("ioc_count", 0)
            },
            "cve_correlation": {
                "matched": correlation_metadata.get("cve_matched", False),
                "matches": cve_results,
                "count": correlation_metadata.get("cve_count", 0)
            },
            "correlation_metadata": {
                "confidence": correlation_metadata.get("confidence", 0),
                "priority": correlation_metadata.get("priority", "LOW"),
                "reason": correlation_metadata.get("reason", "")
            }
        }
