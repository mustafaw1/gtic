"""
OTX Domain Fetcher Service
Optimized with streaming, lazy loading, and memory management
"""

import json
import logging
import asyncio
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path
import aiohttp
import zstandard as zstd
import tracemalloc
from app.services.utils import gtic_threat_score
from config import IngestionServiceSettings
from database.connection import IngestionDatabase
from models.iocs_record import DomainCacheRecord, IPCacheRecord, HashCacheRecord, ProcessingStats

logger = logging.getLogger(__name__)


class OTXDomainFetcher:
    """Optimized OTX domain fetcher with streaming and memory management"""
    
    def __init__(self, settings: IngestionServiceSettings, database: IngestionDatabase):
        self.settings = settings
        self.database = database
        
        if not settings.OTX_API_KEY:
            raise ValueError("OTX_API_KEY not found in configuration")
        
        self._session = None
        self._compressor = None
        self._headers = {
            'X-OTX-API-KEY': settings.OTX_API_KEY,
            'User-Agent': 'GTIC OTX Ingestion Service 1.0'
        }
        
        self.processed_pulses_file = Path("otx_processed_pulses.json")
        self.processed_pulses = self._load_processed_pulses()
        
        try:
            if not tracemalloc.is_tracing():
                tracemalloc.start()
        except Exception as e:
            logger.warning(f"Could not start tracemalloc: {e}")

    async def get_session(self):
        """Lazy initialization of aiohttp session"""
        if self._session is None:
            connector = aiohttp.TCPConnector(
                limit=self.settings.http_connection_limit,
                limit_per_host=self.settings.http_per_host_limit,
                keepalive_timeout=30
            )
            self._session = aiohttp.ClientSession(
                headers=self._headers,
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=30)
            )
            logger.debug("Initialized optimized aiohttp session")
        return self._session
    
    def get_compressor(self):
        """Lazy initialization of zstd compressor"""
        if self._compressor is None:
            self._compressor = zstd.ZstdCompressor(level=3)
            logger.debug("Initialized zstd compressor")
        return self._compressor
    
    async def close_session(self):
        """Properly close the session"""
        if self._session:
            await self._session.close()
            self._session = None
    
    def _load_processed_pulses(self) -> Dict[str, datetime]:
        """Load list of already processed pulse IDs with timestamps"""
        if self.processed_pulses_file.exists():
            try:
                with open(self.processed_pulses_file, 'r') as f:
                    data = json.load(f)
                return {
                    pulse_id: datetime.fromisoformat(timestamp)
                    for pulse_id, timestamp in data.items()
                }
            except Exception as e:
                logger.warning(f"Could not load processed pulses: {e}")
        return {}
    
    def _save_processed_pulses(self):
        """Save processed pulse IDs to file"""
        try:
            data = {
                pulse_id: timestamp.isoformat()
                for pulse_id, timestamp in self.processed_pulses.items()
            }
            with open(self.processed_pulses_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Could not save processed pulses: {e}")
    
    def _should_skip_pulse(self, pulse_id: str) -> bool:
        """Check if pulse should be skipped (recently processed)"""
        if pulse_id in self.processed_pulses:
            last_processed = self.processed_pulses[pulse_id]
            time_since_processed = datetime.now(timezone.utc) - last_processed
            return time_since_processed < timedelta(hours=6)
        return False
    
    async def run(self) -> ProcessingStats:
        """Main execution method with streaming processing"""
        logger.info("Starting OTX pulse processing (streaming all available pulses)")
        start_time = datetime.now()
        peak_memory_bytes = 0
        stats = ProcessingStats()
        
        try:
            pulse_list = await self.fetch_pulse_list()
            
            if not pulse_list:
                logger.info("No pulses found to process")
                return stats
            
            logger.info(f"Found {len(pulse_list)} pulses available for processing")

            for i, pulse_info in enumerate(pulse_list):
                pulse_id = pulse_info.get('id')
                pulse_name = pulse_info.get('name', 'Unknown')
                
                if self._should_skip_pulse(pulse_id):
                    stats.pulses_skipped += 1
                    logger.debug(f"Skipping recently processed pulse: {pulse_name}")
                    continue

                pulse_stats = await self._process_single_pulse_streaming(pulse_info)
                if pulse_stats['success']:
                    self.processed_pulses[pulse_id] = datetime.now(timezone.utc)
                    stats.pulses_processed += 1
                    stats.total_domains_processed += pulse_stats['domains_processed']
                    stats.domains_newly_stored += pulse_stats['domains_stored']
                    stats.domains_already_existed += pulse_stats['domains_existed']
                    stats.total_ips_processed += pulse_stats['ips_processed']
                    stats.ips_newly_stored += pulse_stats['ips_stored']
                    stats.ips_already_existed += pulse_stats['ips_existed']
                    stats.total_hashes_processed += pulse_stats['hashes_processed']
                    stats.hashes_newly_stored += pulse_stats['hashes_stored']
                    stats.hashes_already_existed += pulse_stats['hashes_existed']
                else:
                    stats.pulses_failed += 1
                    logger.error(f"✗ Pulse '{pulse_name}' failed: {pulse_stats.get('error', 'Unknown error')}")
                
                self._save_processed_pulses()
                
                try:
                    if tracemalloc.is_tracing():
                        current_snapshot = tracemalloc.take_snapshot()
                        current_memory = sum(stat.size for stat in current_snapshot.statistics('lineno')[:10])
                        peak_memory_bytes = max(peak_memory_bytes, current_memory)
                except Exception as e:
                    logger.debug(f"Memory snapshot failed: {e}")
                if i < len(pulse_list) - 1:
                    logger.debug(f"Waiting {self.settings.otx_pulse_delay}s before next pulse...")
                    await asyncio.sleep(self.settings.otx_pulse_delay)
            
            processing_time = (datetime.now() - start_time).total_seconds()
            stats.processing_time_seconds = processing_time
            stats.memory_peak_mb = peak_memory_bytes / (1024 * 1024)
            
            logger.info(f"Streaming pulse processing completed: {stats.model_dump()}")
            logger.info(f"Peak memory usage: {stats.memory_peak_mb:.1f}MB")
            return stats
            
        finally:
            await self.close_session()
            if tracemalloc.is_tracing():
                tracemalloc.stop()
    
    async def fetch_pulse_list(self) -> List[Dict[str, Any]]:
        """Fetch list of recent pulses (metadata only) using streaming"""
        pulses = []
        session = await self.get_session()
        
        try:
            for page in range(1, 3):
                logger.debug(f"Fetching pulse list page {page}")
                
                url = f"{self.settings.otx_base_url}/pulses/subscribed"
                params = {'limit': 50, 'page': page, 'sort': '-created'}
                
                async with session.get(url, params=params) as response:
                    response.raise_for_status()
                    data = await response.json()
                
                page_pulses = data.get('results', [])
                if not page_pulses:
                    break

                for pulse in page_pulses:
                    pulses.append({
                        'id': pulse.get('id'),
                        'name': pulse.get('name', 'Unknown'),
                        'created': pulse.get('created'),
                        'indicator_count': len(pulse.get('indicators', []))
                    })
                
                await asyncio.sleep(0.5)

            return pulses
            
        except Exception as e:
            logger.error(f"Error fetching pulse list: {e}")
            return []
    
    async def _process_single_pulse_streaming(self, pulse_info: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single pulse with streaming domain batches"""
        pulse_id = pulse_info['id']
        pulse_name = pulse_info.get('name', 'Unknown')
        
        result = {
            'success': False,
            'domains_processed': 0,
            'domains_stored': 0,
            'domains_existed': 0,
            'ips_processed': 0,
            'ips_stored': 0,
            'ips_existed': 0,
            'hashes_processed': 0,
            'hashes_stored': 0,
            'hashes_existed': 0,
            'error': None
        }
        
        snapshot1 = None
        try:
            if tracemalloc.is_tracing():
                snapshot1 = tracemalloc.take_snapshot()
        except Exception as e:
            logger.debug(f"Initial memory snapshot failed: {e}")
        
        try:
            full_pulse = await self._fetch_full_pulse(pulse_id)
            if not full_pulse:
                result['error'] = "Could not fetch full pulse data"
                return result
            
            domains = self._extract_domains_from_pulse(full_pulse)
            ips = self._extract_ips_from_pulse(full_pulse)
            hashes = self._extract_hashes_from_pulse(full_pulse)
            result['domains_processed'] = len(domains)
            result['ips_processed'] = len(ips)
            result['hashes_processed'] = len(hashes)
            
            if not domains and not ips and not hashes:
                logger.debug(f"No domains, IPs, or hashes found in pulse: {pulse_name}")
                result['success'] = True
                return result
            
            existing_domains = await self.database.get_existing_domains(domains)
            new_domains = [d for d in domains if d not in existing_domains]
            result['domains_existed'] = len(existing_domains)
            
            existing_ips = await self.database.get_existing_ips(ips)
            new_ips = [ip for ip in ips if ip not in existing_ips]
            result['ips_existed'] = len(existing_ips)
            
            existing_hashes = await self.database.get_existing_hashes(hashes)
            new_hashes = [h for h in hashes if h not in existing_hashes]
            result['hashes_existed'] = len(existing_hashes)
            
            if not new_domains and not new_ips and not new_hashes:
                logger.debug(f"All domains, IPs, and hashes already exist for pulse: {pulse_name}")
                result['success'] = True
                return result
            
            domains_stored = 0
            ips_stored = 0
            hashes_stored = 0
            batch_size = self.settings.batch_size
            
            if new_domains:
                for i in range(0, len(new_domains), batch_size):
                    batch = new_domains[i:i + batch_size]
                    batch_records = []
                    
                    for domain in batch:
                        try:
                            domain_data = await self.fetch_domain_details(domain)
                            if domain_data:
                                record = self.map_otx_to_domain_cache(domain_data, domain)
                                batch_records.append(record)
                            
                            await asyncio.sleep(0.1)
                            
                        except Exception as e:
                            logger.warning(f"Failed to process domain {domain}: {e}")
                            continue
                    
                    if batch_records:
                        batch_stored = await self.database.store_batch(batch_records)
                        domains_stored += batch_stored
                        del batch_records
                    
                    if i + batch_size < len(new_domains):
                        await asyncio.sleep(0.5)
            
            if new_ips:
                for i in range(0, len(new_ips), batch_size):
                    batch = new_ips[i:i + batch_size]
                    batch_records = []
                    
                    for ip in batch:
                        try:
                            ip_data = await self.fetch_ip_details(ip)
                            if ip_data:
                                record = self.map_otx_to_ip_cache(ip_data, ip)
                                batch_records.append(record)
                            
                            await asyncio.sleep(0.1)
                            
                        except Exception as e:
                            logger.warning(f"Failed to process IP {ip}: {e}")
                            continue
                    
                    if batch_records:
                        batch_stored = await self.database.store_ip_batch(batch_records)
                        ips_stored += batch_stored
                        del batch_records
                    
                    if i + batch_size < len(new_ips):
                        await asyncio.sleep(0.5)
            
            if new_hashes:
                for i in range(0, len(new_hashes), batch_size):
                    batch = new_hashes[i:i + batch_size]
                    batch_records = []
                    
                    for hash_value, hash_type in batch:
                        try:
                            hash_data = await self.fetch_hash_details(hash_value, hash_type)
                            if hash_data:
                                record = self.map_otx_to_hash_cache(hash_data, hash_value, hash_type)
                                batch_records.append(record)
                            
                            await asyncio.sleep(0.1)
                            
                        except Exception as e:
                            logger.warning(f"Failed to process hash {hash_value}: {e}")
                            continue
                    
                    if batch_records:
                        batch_stored = await self.database.store_hash_batch(batch_records)
                        hashes_stored += batch_stored
                        del batch_records
                    
                    if i + batch_size < len(new_hashes):
                        await asyncio.sleep(0.5)
            
            result['domains_stored'] = domains_stored
            result['ips_stored'] = ips_stored
            result['hashes_stored'] = hashes_stored
            result['success'] = True
            
            try:
                if tracemalloc.is_tracing() and snapshot1:
                    snapshot2 = tracemalloc.take_snapshot()
                    top_stats = snapshot2.compare_to(snapshot1, 'lineno')
                    if top_stats:
                        memory_delta = sum(stat.size_diff for stat in top_stats[:5])
                        logger.debug(f"Pulse {pulse_name} memory delta: {memory_delta / 1024:.1f} KB")
            except Exception as e:
                logger.debug(f"Memory comparison failed: {e}")
            
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Error processing pulse {pulse_name}: {e}")
        
        return result
    
    async def _fetch_full_pulse(self, pulse_id: str) -> Optional[Dict[str, Any]]:
        """Fetch full pulse data including indicators"""
        session = await self.get_session()
        try:
            url = f"{self.settings.otx_base_url}/pulses/{pulse_id}"
            async with session.get(url) as response:
                response.raise_for_status()
                return await response.json()
        except Exception as e:
            logger.error(f"Failed to fetch full pulse {pulse_id}: {e}")
            return None
    
    def _extract_domains_from_pulse(self, pulse: Dict[str, Any]) -> List[str]:
        """Extract domain indicators from a pulse"""
        domains = set()
        
        try:
            indicators = pulse.get('indicators', [])
            for indicator in indicators:
                if indicator.get('type') in ['domain', 'hostname', 'FQDN']:
                    domain = indicator.get('indicator', '').strip().lower()
                    if domain and self.is_valid_domain(domain):
                        domains.add(domain)
            
            return list(domains)
            
        except Exception as e:
            logger.error(f"Error extracting domains from pulse: {e}")
            return []
    
    def _extract_ips_from_pulse(self, pulse: Dict[str, Any]) -> List[str]:
        """Extract IP indicators from a pulse"""
        ips = set()
        
        try:
            indicators = pulse.get('indicators', [])
            for indicator in indicators:
                if indicator.get('type') in ['IPv4', 'IPv6']:
                    ip = indicator.get('indicator', '').strip()
                    if ip and self.is_valid_ip(ip):
                        ips.add(ip)
            
            return list(ips)
            
        except Exception as e:
            logger.error(f"Error extracting IPs from pulse: {e}")
            return []
    
    def _extract_hashes_from_pulse(self, pulse: Dict[str, Any]) -> List[tuple]:
        """Extract hash indicators from a pulse
        Returns:
            List of (hash_value, hash_type) tuples
        """
        hashes = set()
        
        try:
            indicators = pulse.get('indicators', [])
            for indicator in indicators:
                indicator_type = indicator.get('type', '').upper()
                if indicator_type in ['FILEHASH-SHA256', 'FILEHASH-SHA1', 'FILEHASH-MD5']:
                    hash_value = indicator.get('indicator', '').strip().lower()
                    if hash_value and self.is_valid_hash(hash_value, indicator_type):
                        hash_type = indicator_type.replace('FILEHASH-', '').lower()
                        hashes.add((hash_value, hash_type))
            
            return list(hashes)
            
        except Exception as e:
            logger.error(f"Error extracting hashes from pulse: {e}")
            return []
    
    async def fetch_domain_details(self, domain: str) -> Optional[Dict[str, Any]]:
        """Fetch detailed threat intel for a domain"""
        session = await self.get_session()
        url = f"{self.settings.otx_base_url}/indicators/domain/{domain}"
        
        try:
            async with session.get(url) as response:
                response.raise_for_status()
                return await response.json()
        except Exception as e:
            logger.debug(f"Failed to fetch details for {domain}: {e}")
            return None
    
    async def fetch_ip_details(self, ip: str) -> Optional[Dict[str, Any]]:
        """Fetch detailed threat intel for an IP"""
        session = await self.get_session()
        url = f"{self.settings.otx_base_url}/indicators/IPv4/{ip}" if ':' not in ip else f"{self.settings.otx_base_url}/indicators/IPv6/{ip}"
        
        try:
            async with session.get(url) as response:
                response.raise_for_status()
                return await response.json()
        except Exception as e:
            logger.debug(f"Failed to fetch details for {ip}: {e}")
            return None
    
    async def fetch_hash_details(self, hash_value: str, hash_type: str) -> Optional[Dict[str, Any]]:
        """Fetch detailed threat intel for a hash"""
        session = await self.get_session()
        hash_type_upper = hash_type.upper()
        url = f"{self.settings.otx_base_url}/indicators/file/{hash_value}"
        
        try:
            async with session.get(url) as response:
                response.raise_for_status()
                return await response.json()
        except Exception as e:
            logger.debug(f"Failed to fetch details for {hash_type} hash {hash_value}: {e}")
            return None
    
    def map_otx_to_domain_cache(self, otx_data: Dict[str, Any], domain: str) -> DomainCacheRecord:
        """Map OTX data to domain cache record"""
        now = datetime.now(timezone.utc)
        
        general_info = otx_data.get('general', {})
        pulse_info = otx_data.get('pulse_info', {})
        pulses = pulse_info.get('pulses', [])
        
        reputation = general_info.get('reputation', 0)
        
        suspicious_pulse_count = self.count_suspicious_pulses(pulses)
        
        if suspicious_pulse_count == 0:
            if reputation < 0:
                threat_score = 0
            else:
                threat_score = 5
        else:
            base_score = min(suspicious_pulse_count * 3, 60)
            
            if reputation > 2:
                reputation_boost = min((reputation - 2) * 2, 10)
                threat_score = min(100, base_score + reputation_boost)
            elif reputation < -2:
                reputation_reduction = abs(reputation + 2) * 2
                threat_score = max(5, base_score - reputation_reduction)
            else:
                threat_score = base_score
        
        if threat_score < 25:
            threat_level = 0
        elif threat_score < 50:
            threat_level = 1
        elif threat_score < 75:
            threat_level = 2
        else:
            threat_level = 3
        
        suspicious_tags = set()
        for pulse in pulses:
            tags = pulse.get('tags') or []
            pulse_tags_lower = {tag.lower() for tag in tags if tag is not None}
            pulse_name = (pulse.get('name') or '').lower()
            pulse_description = (pulse.get('description') or '').lower()
            
            is_suspicious = (
                bool(pulse_tags_lower.intersection(self._get_malicious_keywords())) or
                any(keyword in pulse_name for keyword in self._get_malicious_keywords()) or
                any(keyword in pulse_description[:100] for keyword in self._get_malicious_keywords())
            )
            
            if is_suspicious:
                suspicious_tags.update(tag for tag in tags if tag is not None)
        
        categories = sorted(list(suspicious_tags)) if suspicious_tags else []
        
        return DomainCacheRecord(
            domain_name=domain.lower().strip(),
            threat_score=gtic_threat_score.normalize_score(min(max(threat_score, 0), 100)),
            threat_level=min(max(threat_level, 0), 3),
            threat_categories=', '.join(categories) if categories else 'Unknown',
            source_name='AlienVault_OTX',
            first_seen=now,
            last_fetched=now,
            details=self._compress_details(otx_data),
            expires_at=self._calculate_expiry_time(threat_level, ', '.join(categories) if categories else ''),
            total_reports=suspicious_pulse_count
        )
    
    def map_otx_to_ip_cache(self, otx_data: Dict[str, Any], ip: str) -> IPCacheRecord:
        """Map OTX data to IP cache record"""
        now = datetime.now(timezone.utc)
        
        general_info = otx_data.get('general', {})
        pulse_info = otx_data.get('pulse_info', {})
        pulses = pulse_info.get('pulses', [])
        
        reputation = general_info.get('reputation', 0)
        country_code = general_info.get('country_code', None)
        
        suspicious_pulse_count = self.count_suspicious_pulses(pulses)
        
        if suspicious_pulse_count == 0:
            if reputation < 0:
                threat_score = 0
            else:
                threat_score = 5
        else:
            base_score = min(suspicious_pulse_count * 3, 60)
            
            if reputation > 2:
                reputation_boost = min((reputation - 2) * 2, 10)
                threat_score = min(100, base_score + reputation_boost)
            elif reputation < -2:
                reputation_reduction = abs(reputation + 2) * 2
                threat_score = max(5, base_score - reputation_reduction)
            else:
                threat_score = base_score
        
        if threat_score < 25:
            threat_level = 0
        elif threat_score < 50:
            threat_level = 1
        elif threat_score < 75:
            threat_level = 2
        else:
            threat_level = 3
        
        suspicious_tags = set()
        for pulse in pulses:
            tags = pulse.get('tags') or []
            pulse_tags_lower = {tag.lower() for tag in tags if tag is not None}
            pulse_name = (pulse.get('name') or '').lower()
            pulse_description = (pulse.get('description') or '').lower()
            
            is_suspicious = (
                bool(pulse_tags_lower.intersection(self._get_malicious_keywords())) or
                any(keyword in pulse_name for keyword in self._get_malicious_keywords()) or
                any(keyword in pulse_description[:100] for keyword in self._get_malicious_keywords())
            )
            
            if is_suspicious:
                suspicious_tags.update(tag for tag in tags if tag is not None)
        
        categories = sorted(list(suspicious_tags)) if suspicious_tags else []
        
        return IPCacheRecord(
            ip_address=ip.strip(),
            threat_score=gtic_threat_score.normalize_score(min(max(threat_score, 0), 100)),
            threat_level=min(max(threat_level, 0), 3),
            threat_categories=', '.join(categories) if categories else 'Unknown',
            source_name='AlienVault_OTX',
            first_seen=now,
            last_fetched=now,
            details=self._compress_details(otx_data),
            expires_at=self._calculate_expiry_time(threat_level, ', '.join(categories) if categories else ''),
            country_code=country_code,
            total_reports=suspicious_pulse_count
        )
    
    def map_otx_to_hash_cache(self, otx_data: Dict[str, Any], hash_value: str, hash_type: str) -> HashCacheRecord:
        """Map OTX data to hash cache record"""
        now = datetime.now(timezone.utc)
        
        general_info = otx_data.get('general', {})
        pulse_info = otx_data.get('pulse_info', {})
        pulses = pulse_info.get('pulses', [])
        
        reputation = general_info.get('reputation', 0)
        
        suspicious_pulse_count = self.count_suspicious_pulses(pulses)
        
        if suspicious_pulse_count == 0:
            if reputation < 0:
                threat_score = 0
            else:
                threat_score = 5
        else:
            base_score = min(suspicious_pulse_count * 3, 60)
            
            if reputation > 2:
                reputation_boost = min((reputation - 2) * 2, 10)
                threat_score = min(100, base_score + reputation_boost)
            elif reputation < -2:
                reputation_reduction = abs(reputation + 2) * 2
                threat_score = max(5, base_score - reputation_reduction)
            else:
                threat_score = base_score
        
        if threat_score < 25:
            threat_level = 0
        elif threat_score < 50:
            threat_level = 1
        elif threat_score < 75:
            threat_level = 2
        else:
            threat_level = 3
        
        suspicious_tags = set()
        for pulse in pulses:
            tags = pulse.get('tags') or []
            pulse_tags_lower = {tag.lower() for tag in tags if tag is not None}
            pulse_name = (pulse.get('name') or '').lower()
            pulse_description = (pulse.get('description') or '').lower()
            
            is_suspicious = (
                bool(pulse_tags_lower.intersection(self._get_malicious_keywords())) or
                any(keyword in pulse_name for keyword in self._get_malicious_keywords()) or
                any(keyword in pulse_description[:100] for keyword in self._get_malicious_keywords())
            )
            
            if is_suspicious:
                suspicious_tags.update(tag for tag in tags if tag is not None)
        
        categories = sorted(list(suspicious_tags)) if suspicious_tags else []
        
        return HashCacheRecord(
            hash_value=hash_value.lower().strip(),
            hash_type=hash_type.lower(),
            threat_score=gtic_threat_score.normalize_score(min(max(threat_score, 0), 100)),
            threat_level=min(max(threat_level, 0), 3),
            threat_categories=', '.join(categories) if categories else 'Unknown',
            source_name='AlienVault_OTX',
            first_seen=now,
            last_fetched=now,
            details=self._compress_details(otx_data),
            expires_at=self._calculate_expiry_time(threat_level, ', '.join(categories) if categories else ''),
            total_reports=suspicious_pulse_count
        )
    
    def _get_malicious_keywords(self) -> set:
        """Get set of malicious keywords for suspicious pulse detection"""
        return {
            'malware', 'trojan', 'virus', 'backdoor', 'spyware', 'stealer', 'ransomware',
            'phishing', 'scam', 'fraud', 'spam', 'botnet', 'c2', 'command-and-control',
            'exploit', 'vulnerability', 'apt', 'cryptomining', 'mining', 'cryptocurrency',
            
            'suspicious', 'malicious', 'blacklist', 'blacklisted', 'blocklist',
            'threat', 'bad', 'evil', 'dangerous', 'harmful', 'attack',
            
            'campaign', 'actor', 'group', 'operation', 'activity',
            
            'ddos', 'bruteforce', 'brute-force', 'scanner', 'scan',
            'injection', 'xss', 'sqli', 'rce', 'lfi', 'rfi'
        }

    def count_suspicious_pulses(self, pulses: List[Dict[str, Any]]) -> int:
        """Count pulses that contain suspicious/malicious indicators"""
        suspicious_count = 0
        malicious_keywords = self._get_malicious_keywords()
        
        for pulse in pulses:
            tags = pulse.get('tags') or []
            pulse_tags_lower = {tag.lower() for tag in tags if tag is not None}
            pulse_name = (pulse.get('name') or '').lower()
            pulse_description = (pulse.get('description') or '').lower()
            
            is_suspicious = (
                bool(pulse_tags_lower.intersection(malicious_keywords)) or
                any(keyword in pulse_name for keyword in malicious_keywords) or
                any(keyword in pulse_description[:100] for keyword in malicious_keywords)
            )
            
            if is_suspicious:
                suspicious_count += 1
        
        return suspicious_count
    
    def _compress_details(self, data: Dict[str, Any]) -> bytes:
        """Compress OTX data using zstd"""
        try:
            sanitized_data = self._sanitize_for_db_json(data)
            json_str = json.dumps(sanitized_data).encode('utf-8')
            compressor = self.get_compressor()
            compressed_data = compressor.compress(json_str)
            logger.debug(f"Compressed OTX data: {len(json_str)} bytes -> {len(compressed_data)} bytes")
            return compressed_data
        except Exception as e:
            logger.error(f"Failed to compress OTX data: {e}")
            return json.dumps(data).encode('utf-8')
    
    def _sanitize_for_db_json(self, data: Any) -> Any:
        """Sanitize data for JSON serialization"""
        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                str_key = str(key) if not isinstance(key, str) else key
                sanitized[str_key] = self._sanitize_for_db_json(value)
            return sanitized
        elif isinstance(data, list):
            return [self._sanitize_for_db_json(item) for item in data]
        elif isinstance(data, (int, float, str, bool)) or data is None:
            return data
        else:
            return str(data)
    
    def _calculate_expiry_time(self, threat_level: int, categories: str = "") -> datetime:
        """Calculate expiry time based on threat level and categories"""
        now = datetime.now(timezone.utc)
        
        if categories:
            category_list = [cat.strip().lower() for cat in categories.split(",")]
            if "malware" in category_list or "phishing" in category_list:
                return now + timedelta(days=30)
            if "suspicious" in category_list:
                return now + timedelta(days=7)
            if "clean" in category_list:
                return now + timedelta(days=1)
        
        if threat_level == 0:
            return now + timedelta(days=1)
        elif threat_level == 1:
            return now + timedelta(days=7)
        elif threat_level == 2:
            return now + timedelta(days=14)
        elif threat_level == 3:
            return now + timedelta(days=30)
        else:
            return now + timedelta(days=1)
    
    def is_valid_domain(self, domain: str) -> bool:
        """Basic domain validation"""
        if not domain or len(domain) > 253:
            return False
        if domain.startswith('.') or domain.endswith('.'):
            return False
        if ' ' in domain or '\\t' in domain:
            return False
        return '.' in domain
    
    def is_valid_ip(self, ip: str) -> bool:
        """Basic IP validation"""
        if not ip or not ip.strip():
            return False
        
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def is_valid_hash(self, hash_value: str, hash_type: str) -> bool:
        """Basic hash validation"""
        if not hash_value or not hash_value.strip():
            return False
        
        hash_value = hash_value.strip().lower()
        
        try:
            int(hash_value, 16)
        except ValueError:
            return False
        
        if hash_type == 'FILEHASH-MD5':
            return len(hash_value) == 32
        elif hash_type == 'FILEHASH-SHA1':
            return len(hash_value) == 40
        elif hash_type == 'FILEHASH-SHA256':
            return len(hash_value) == 64
        
        return False
