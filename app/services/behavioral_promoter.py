"""
When the anomaly detection engine flags an IP with HIGH or CRITICAL severity
(rule_tier >= 2) and no external threat intelligence source confirms it, this
service writes an internally-derived threat record directly into the GTIC cache
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

from app.services.lookup_client import get_lookup_client

logger = logging.getLogger(__name__)

BEHAVIORAL_SOURCE = "Overpower"
PROMOTION_THRESHOLD = 2

_TIER_TO_THREAT: Dict[int, tuple] = {
    2: (7, 2),
    3: (9, 3),
}

_DEFAULT_CATEGORIES: Dict[int, str] = {
    2: "behavioral-detection",
    3: "behavioral-detection, critical-threat",
}

_LEVEL_TO_TTL_DAYS: Dict[int, int] = {
    2: 7,
    3: 30,
}


class BehavioralPromoterService:
    """Promotes behaviorally-detected IPs to malicious status in the GTIC."""

    @staticmethod
    async def promote_ip(
        ip_address: str,
        rule_tier: int,
        log_id: str,
        threat_categories: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Attempt to promote an IP to malicious status in the GTIC.

        An entry is written only when:
          - rule_tier is at least PROMOTION_THRESHOLD (2 = HIGH)
          - the new threat_score exceeds any already-cached score for that IP
            (existing entries are never downgraded)

        Args:
            ip_address:        The IP to promote.
            rule_tier:         Detection severity (0-3).
            log_id:            Detection log identifier.
            threat_categories: Optional comma-separated threat tags.
            agent_id:          Optional ID of the reporting agent.

        Returns:
            Dict with keys: promoted (bool), threat_score, threat_level,
            threat_categories, source_api, message.
        """
        if rule_tier < PROMOTION_THRESHOLD:
            return {
                "promoted": False,
                "threat_score": 0,
                "threat_level": 0,
                "threat_categories": "",
                "source_api": "",
                "message": (
                    f"rule_tier {rule_tier} is below the promotion threshold "
                    f"({PROMOTION_THRESHOLD}). Only HIGH (2) and CRITICAL (3) "
                    "detections are promoted to the GTIC."
                ),
            }

        threat_score, threat_level = _TIER_TO_THREAT[rule_tier]
        categories = threat_categories or _DEFAULT_CATEGORIES[rule_tier]
        ttl_days = _LEVEL_TO_TTL_DAYS[rule_tier]

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=ttl_days)

        threat_record = {
            "ip_address": ip_address,
            "threat_score": threat_score,
            "threat_level": threat_level,
            "threat_categories": categories,
            "source_name": BEHAVIORAL_SOURCE,
            "country_code": None,
            "total_reports": 1,
            "first_seen": now.isoformat(),
            "last_fetched": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "raw_data": {
                "source": BEHAVIORAL_SOURCE,
                "rule_tier": rule_tier,
                "agent_id": agent_id,
                "log_id": log_id,
                "detected_at": now.isoformat(),
            },
        }

        try:
            lookup_client = await get_lookup_client()
            result = await lookup_client.promote_behavioral_ioc(threat_record)

            return {
                "promoted": result.get("stored", False),
                "threat_score": result.get("threat_score", threat_score),
                "threat_level": threat_level,
                "threat_categories": categories,
                "source_api": BEHAVIORAL_SOURCE,
                "message": result.get("message", "Promotion completed"),
            }

        except Exception as e:
            logger.error(f"Failed to promote IP {ip_address} to GTIC: {e}")
            raise
