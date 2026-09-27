"""PostgreSQL repository implementation for CVE vulnerability data."""

import json
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import asyncio
import time

import asyncpg
import zstandard as zstd

from ..interfaces.database import DatabaseRepositoryInterface
from ..resource_manager import get_resource_manager, ResourceType
from ..models.cve_data import CVEData, CVEId

logger = logging.getLogger(__name__)

_SQL_EXCLUDE_REJECTED_DEFERRED = (
    "AND (c.cve_status IS NULL OR c.cve_status NOT IN ('Rejected', 'Deferred'))"
)


class CVEPostgreSQLRepository(DatabaseRepositoryInterface):
    """PostgreSQL implementation for CVE database repository"""
    
    def __init__(self, db_pool: Optional[asyncpg.Pool] = None, connection_params: Optional[Dict] = None):
        self.db_pool = db_pool
        self.connection_params = connection_params or {}
        self.schema = 'public'
        self.table_name = 'cve_cache'
        self._lock = asyncio.Lock()
        self._resource_manager = get_resource_manager()
        self._connection_timeout = 30.0
        self._max_retries = 3
        self._retry_delay = 1.0
        
        self.zstd_compressor = zstd.ZstdCompressor(level=3)
        self.zstd_decompressor = zstd.ZstdDecompressor()
    
    async def _acquire_connection_with_retry(self):
        """Acquire database connection with retry logic"""
        for attempt in range(self._max_retries):
            try:
                connection_id = f"cve_db_conn_{time.time()}_{attempt}"
                connection = await asyncio.wait_for(
                    self.db_pool.acquire(),
                    timeout=self._connection_timeout
                )
                
                self._resource_manager.register_resource(
                    resource_id=connection_id,
                    resource_type=ResourceType.DATABASE_CONNECTION,
                    metadata={
                        "pool_size": len(self.db_pool._holders),
                        "pool_max": self.db_pool._maxsize,
                        "acquired_at": time.time()
                    }
                )
                
                return connection, connection_id
                
            except asyncio.TimeoutError:
                logger.warning(f"CVE DB connection timeout on attempt {attempt + 1}/{self._max_retries}")
                if attempt == self._max_retries - 1:
                    raise RuntimeError("CVE database connection pool exhausted")
                    
            except Exception as e:
                logger.error(f"CVE DB connection error on attempt {attempt + 1}/{self._max_retries}: {e}")
                if attempt == self._max_retries - 1:
                    raise
                    
            await asyncio.sleep(self._retry_delay * (2 ** attempt))
        
        raise RuntimeError("Failed to acquire CVE database connection after all retries")
    
    async def _release_connection(self, connection, connection_id: str):
        """Release database connection"""
        try:
            if connection:
                await self.db_pool.release(connection)
                await self._resource_manager.unregister_resource(connection_id)
        except Exception as e:
            logger.error(f"Error releasing CVE DB connection {connection_id}: {e}")
    
    async def find_by_cve_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Find CVE data by CVE ID"""
        if not self.db_pool:
            raise RuntimeError("Database pool not available")
        
        connection = None
        connection_id = None
        try:
            connection, connection_id = await self._acquire_connection_with_retry()
            
            query = f"""
                SELECT
                    cve_id, configurations, cvss_score, threat_level, cve_status, published, last_modified,
                    source_name, first_seen, last_fetched, details, expires_at, is_kev,
                    cvss_v3_vector_string, description, epss_score
                FROM {self.schema}.{self.table_name}
                WHERE cve_id = $1
            """
            
            result = await connection.fetchrow(query, cve_id)
            
            if result:
                data = dict(result)
                
                for col in ['published', 'last_modified', 'first_seen', 'last_fetched', 'expires_at']:
                    dt = data.get(col)
                    if dt and dt.tzinfo is None:
                        data[col] = dt.replace(tzinfo=timezone.utc)
                
                if data.get('details'):
                    try:
                        decompressed = self.zstd_decompressor.decompress(data['details'])
                        raw_data = json.loads(decompressed.decode('utf-8'))
                        data['raw_data'] = raw_data
                        data['weaknesses'] = raw_data.get('weaknesses')
                        data['references'] = raw_data.get('references')
                        data['cisa_required_action'] = raw_data.get('cisaRequiredAction') or raw_data.get('cisa_required_action')
                        data['cisa_vulnerability_name'] = raw_data.get('cisaVulnerabilityName') or raw_data.get('cisa_vulnerability_name')
                        _exploit_add = raw_data.get('cisaExploitAdd') or raw_data.get('cisa_exploit_add')
                        _action_due = raw_data.get('cisaActionDue') or raw_data.get('cisa_action_due')
                        data['cisa_exploit_add'] = datetime.strptime(_exploit_add, '%Y-%m-%d').replace(tzinfo=timezone.utc) if isinstance(_exploit_add, str) else _exploit_add
                        data['cisa_action_due'] = datetime.strptime(_action_due, '%Y-%m-%d').replace(tzinfo=timezone.utc) if isinstance(_action_due, str) else _action_due
                        if not data.get('cvss_v3_vector_string'):
                            metrics = raw_data.get('metrics', {})
                            cvss_v31 = metrics.get('cvssMetricV31', []) or metrics.get('cvssMetricV30', [])
                            if cvss_v31:
                                data['cvss_v3_vector_string'] = cvss_v31[0].get('cvssData', {}).get('vectorString')
                    except Exception as e:
                        logger.warning(f"Failed to decompress details for CVE {cve_id}: {e}")
                        data['raw_data'] = None
                        data['weaknesses'] = None
                        data['references'] = None
                        data['cisa_required_action'] = None
                        data['cisa_vulnerability_name'] = None
                        data['cisa_exploit_add'] = None
                        data['cisa_action_due'] = None
                else:
                    data['raw_data'] = None
                    data['weaknesses'] = None
                    data['references'] = None
                    data['cisa_required_action'] = None
                    data['cisa_vulnerability_name'] = None
                    data['cisa_exploit_add'] = None
                    data['cisa_action_due'] = None
                
                data['id'] = data.get('cve_id')
                raw_score = float(data.get('cvss_score') or 0.0)
                data['score'] = raw_score / 10.0 if raw_score > 10.0 else raw_score
                threat_level = data.get('threat_level', 0)
                severity_map = {3: "CRITICAL", 2: "HIGH", 1: "MEDIUM", 0: "LOW"}
                data['severity'] = severity_map.get(threat_level, "NONE")
                data['vuln_status'] = data.get('cve_status')
                data['source_identifier'] = data.get('source_name')
                data['first_fetched'] = data.get('first_seen')
                data['description_en'] = data.pop('description', None)
                epss = data.get('epss_score')
                data['epss_score'] = float(epss) if epss is not None else None

                cpe_rows = await connection.fetch(
                    f"SELECT cpe_string FROM {self.schema}.cve_cpe WHERE cve_id = $1 ORDER BY cpe_string",
                    cve_id,
                )
                data['affected_cpes'] = [row['cpe_string'] for row in cpe_rows]

                logger.debug(f"Found CVE data in database: {cve_id}")
                return data
            
            logger.debug(f"CVE not found in database: {cve_id}")
            return None

        except Exception as e:
            logger.error(f"Error finding CVE {cve_id} in database: {e}")
            return None
        finally:
            if connection and connection_id:
                await self._release_connection(connection, connection_id)

    async def find_cpes_by_cve_id(self, cve_id: str) -> List[str]:
        """Return all CPE strings associated with a CVE ID."""
        if not self.db_pool:
            return []
        connection = None
        connection_id = None
        try:
            connection, connection_id = await self._acquire_connection_with_retry()
            rows = await connection.fetch(
                f"SELECT cpe_string FROM {self.schema}.cve_cpe WHERE cve_id = $1 ORDER BY cpe_string",
                cve_id,
            )
            return [row['cpe_string'] for row in rows]
        except Exception as e:
            logger.error(f"Error fetching CPEs for CVE {cve_id}: {e}")
            return []
        finally:
            if connection and connection_id:
                await self._release_connection(connection, connection_id)


    @staticmethod
    def _parse_cpe_version(cpe_string: str) -> Optional[str]:
        """Extract version component (index 5) from a CPE 2.3 string."""
        parts = cpe_string.split(':')
        if len(parts) > 5:
            v = parts[5]
            return None if v in ('*', '-', '') else v
        return None

    @staticmethod
    def _cpe_dict_match(input_parts: list, stored_parts: list) -> bool:
        """Match input CPE against a stored CPE dictionary entry.

        Mirrors NVD CPE dictionary search (literal match):
          - input '*'           → matches any stored value
          - input specific value → stored must equal that value exactly
          - stored '*'          → does NOT match a specific input value
        Checks components 6-12 (update → other).
        """
        for i in range(6, 13):
            inp = input_parts[i] if len(input_parts) > i else '*'
            sto = stored_parts[i] if len(stored_parts) > i else '*'
            if inp != '*' and sto != inp:
                return False
        return True

    @staticmethod
    def _normalize_version_str(ver: str) -> str:
        """
        Normalize NVD version strings to PEP 440 format.
        NVD uses formats like '2.0-beta9', '2.0-alpha1', '2.0-rc1'
        which are not valid PEP 440 but map cleanly to '2.0b9', '2.0a1', '2.0rc1'.
        OpenSSL uses letter suffixes (1.0.1f, 1.0.1g) — convert to numeric
        patch segment (1.0.1.6, 1.0.1.7) so PEP 440 can compare them.
        """
        import re
        ver = re.sub(r'[-_]beta\.?(\d*)', lambda m: f'b{m.group(1) or "0"}', ver, flags=re.IGNORECASE)
        ver = re.sub(r'[-_]alpha\.?(\d*)', lambda m: f'a{m.group(1) or "0"}', ver, flags=re.IGNORECASE)
        ver = re.sub(r'[-_]rc\.?(\d*)', lambda m: f'rc{m.group(1) or "0"}', ver, flags=re.IGNORECASE)
        # OpenSSL-style: 1.0.1f → 1.0.1.6  (a=1, b=2, … z=26)
        ver = re.sub(
            r'^(\d+(?:\.\d+)*)([a-z])$',
            lambda m: f"{m.group(1)}.{ord(m.group(2)) - ord('a') + 1}",
            ver,
        )
        return ver

    @staticmethod
    def _version_in_range(
        version: str,
        start_incl: Optional[str],
        start_excl: Optional[str],
        end_incl: Optional[str],
        end_excl: Optional[str],
    ) -> bool:
        """
        Compare a dot-separated version string against NVD version range fields.
        Returns True if the version falls within the range.
        """
        from packaging.version import Version, InvalidVersion

        def parse(ver: str) -> Version:
            try:
                return Version(ver)
            except InvalidVersion:
                return Version(CVEPostgreSQLRepository._normalize_version_str(ver))

        try:
            v = parse(version)
            if start_incl and v < parse(start_incl):
                return False
            if start_excl and v <= parse(start_excl):
                return False
            if end_incl and v > parse(end_incl):
                return False
            if end_excl and v >= parse(end_excl):
                return False
            return True
        except Exception:
            return False

    def _hydrate_row(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalise a raw DB row dict into the standard CVE response shape."""
        matched_cpe = data.get('matched_cpe')
        cpe_base = data.get('cpe_base')
        if not cpe_base and matched_cpe:
            parts = matched_cpe.split(':')
            cpe_base = ':'.join(parts[:5]) if len(parts) >= 5 else matched_cpe

        version_details = {k: v for k, v in {
            'version_start_including': data.get('version_start_including'),
            'version_start_excluding': data.get('version_start_excluding'),
            'version_end_including':   data.get('version_end_including'),
            'version_end_excluding':   data.get('version_end_excluding'),
        }.items() if v is not None}

        criteria = None
        if matched_cpe or cpe_base:
            criteria = {
                'criteria': matched_cpe or cpe_base,
                'vulnerable': data.get('vulnerable', True),
                **version_details,
            }
        data['criteria'] = criteria

        details_bytes = data.get('details')
        if details_bytes:
            try:
                decompressed = self.zstd_decompressor.decompress(details_bytes)
                raw_data = json.loads(decompressed.decode('utf-8'))
                data['weaknesses'] = raw_data.get('weaknesses')
                data['references'] = raw_data.get('references')
                data['cisa_required_action'] = raw_data.get('cisaRequiredAction') or raw_data.get('cisa_required_action')
                data['cisa_vulnerability_name'] = raw_data.get('cisaVulnerabilityName') or raw_data.get('cisa_vulnerability_name')
                _exploit_add = raw_data.get('cisaExploitAdd') or raw_data.get('cisa_exploit_add')
                _action_due = raw_data.get('cisaActionDue') or raw_data.get('cisa_action_due')
                data['cisa_exploit_add'] = datetime.strptime(_exploit_add, '%Y-%m-%d').replace(tzinfo=timezone.utc) if isinstance(_exploit_add, str) else _exploit_add
                data['cisa_action_due'] = datetime.strptime(_action_due, '%Y-%m-%d').replace(tzinfo=timezone.utc) if isinstance(_action_due, str) else _action_due
                if not data.get('cvss_v3_vector_string') or not float(data.get('cvss_score') or 0):
                    metrics = raw_data.get('metrics', {})
                    cvss_v31 = metrics.get('cvssMetricV31', []) or metrics.get('cvssMetricV30', [])
                    if cvss_v31:
                        cvss_data = cvss_v31[0].get('cvssData', {})
                        if not data.get('cvss_v3_vector_string'):
                            data['cvss_v3_vector_string'] = cvss_data.get('vectorString')
                        if not float(data.get('cvss_score') or 0):
                            backfill_score = cvss_data.get('baseScore', 0.0)
                            backfill_severity = cvss_data.get('baseSeverity', '')
                            if backfill_score:
                                data['cvss_score'] = int(backfill_score * 10)
                                severity_to_level = {'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0}
                                data['threat_level'] = severity_to_level.get(backfill_severity.upper(), 0)
            except Exception as e:
                cve_id = data.get('cve_id', 'unknown')
                logger.warning(f"Failed to decompress details for CVE {cve_id}: {e}")
                data.setdefault('weaknesses', None)
                data.setdefault('references', None)
                data.setdefault('cisa_required_action', None)
                data.setdefault('cisa_vulnerability_name', None)
                data.setdefault('cisa_exploit_add', None)
                data.setdefault('cisa_action_due', None)
        else:
            data.setdefault('weaknesses', None)
            data.setdefault('references', None)
            data.setdefault('cisa_required_action', None)
            data.setdefault('cisa_vulnerability_name', None)
            data.setdefault('cisa_exploit_add', None)
            data.setdefault('cisa_action_due', None)

        raw_configs = data.get('configurations')
        if raw_configs:
            try:
                data['configurations'] = json.loads(raw_configs) if isinstance(raw_configs, str) else raw_configs
            except Exception:
                data['configurations'] = []
        else:
            data['configurations'] = []

        for col in ('version_start_including', 'version_start_excluding',
                    'version_end_including', 'version_end_excluding',
                    'matched_cpe', 'cpe_base', 'details', 'vulnerable'):
            data.pop(col, None)

        for col in ['published', 'last_modified', 'first_seen', 'last_fetched', 'expires_at']:
            dt = data.get(col)
            if dt and dt.tzinfo is None:
                data[col] = dt.replace(tzinfo=timezone.utc)

        data['raw_data'] = None
        data['id'] = data.get('cve_id')
        raw_score = float(data.get('cvss_score') or 0.0)
        data['score'] = raw_score / 10.0 if raw_score > 10.0 else raw_score
        severity_map = {3: "CRITICAL", 2: "HIGH", 1: "MEDIUM", 0: "LOW"}
        data['severity'] = severity_map.get(data.get('threat_level', 0), "NONE")
        data['vuln_status'] = data.get('cve_status')
        data['source_identifier'] = data.get('source_name')
        data['first_fetched'] = data.get('first_seen')
        data['description_en'] = data.pop('description', None)
        data['cvss_v3_vector_string'] = data.get('cvss_v3_vector_string')
        epss = data.get('epss_score')
        data['epss_score'] = float(epss) if epss is not None else None
        return data

    async def find_by_cpe(self, cpe_string: str) -> List[Dict[str, Any]]:
        """
        Find CVEs matching a CPE string.

        Three-pass match (NVD-equivalent):
          1. Point: base + version match, wildcard-aware on update/edition components
          2. Wildcard version: all CVEs for the product when input version is *
          3. Range: version falls within NVD version range bounds
        """
        if not self.db_pool:
            raise RuntimeError("Database pool not available")

        parts = cpe_string.split(':')
        cpe_base = ':'.join(parts[:5]) if len(parts) >= 5 else cpe_string
        input_version = self._parse_cpe_version(cpe_string)

        version_val = parts[5] if len(parts) > 5 else '*'
        update_val  = parts[6] if len(parts) > 6 else '*'

        connection = None
        connection_id = None
        try:
            connection, connection_id = await self._acquire_connection_with_retry()

            # CPE dictionary gate: check version is registered and all non-wildcard
            # components match a stored entry exactly (NVD CPE dictionary literal search).
            if version_val not in ('*', ''):
                dict_rows = await connection.fetch(
                    "SELECT cpe_name FROM public.cpe_dictionary WHERE cpe_base = $1 AND COALESCE(version, '-') = $2",
                    cpe_base, version_val,
                )
                if not any(self._cpe_dict_match(parts, r['cpe_name'].split(':')) for r in dict_rows):
                    logger.debug(f"CPE not in dictionary, skipping: {cpe_string}")
                    return []

            # Pass 1 — point-CPE match: same base, same version, update wildcard-aware.
            # Includes version='-' (N/A) so exact CPE matches like windows_server_2022:-:... are found.
            exact_results = []
            if version_val not in ('*', ''):
                exact_results = await connection.fetch(f"""
                    SELECT DISTINCT
                        cp.cpe_string AS matched_cpe,
                        c.cve_id, c.cvss_score, c.threat_level, c.cve_status,
                        c.published, c.last_modified, c.source_name, c.first_seen, c.last_fetched,
                        c.expires_at, c.is_kev, c.description, c.cvss_v3_vector_string, c.epss_score,
                        c.details, c.configurations,
                        cp.vulnerable, cp.version_start_including, cp.version_start_excluding,
                        cp.version_end_including, cp.version_end_excluding
                    FROM {self.schema}.{self.table_name} c
                    JOIN public.cve_cpe cp ON cp.cve_id = c.cve_id
                    WHERE cp.cpe_base = $1
                      AND split_part(cp.cpe_string, ':', 6) = $2
                      AND ($3 = '*' OR split_part(cp.cpe_string, ':', 7) = $3
                                    OR split_part(cp.cpe_string, ':', 7) = '*')
                      AND cp.version_start_including IS NULL
                      AND cp.version_start_excluding IS NULL
                      AND cp.version_end_including   IS NULL
                      AND cp.version_end_excluding   IS NULL
                      AND cp.vulnerable = TRUE
                      {_SQL_EXCLUDE_REJECTED_DEFERRED}
                    ORDER BY c.cvss_score DESC, c.threat_level DESC
                """, cpe_base, version_val, update_val)

            exact_cve_ids = {row['cve_id'] for row in exact_results}

            input_parts = cpe_string.split(':')
            input_version_field = input_parts[5] if len(input_parts) > 5 else ''

            wildcard_results = []
            if input_version_field == '*':
                base_rows = await connection.fetch(f"""
                    SELECT DISTINCT
                        cp.cpe_base,
                        c.cve_id, c.cvss_score, c.threat_level, c.cve_status,
                        c.published, c.last_modified, c.source_name, c.first_seen, c.last_fetched,
                        c.expires_at, c.is_kev, c.description, c.cvss_v3_vector_string, c.epss_score,
                        c.details, c.configurations,
                        cp.vulnerable, cp.version_start_including, cp.version_start_excluding,
                        cp.version_end_including, cp.version_end_excluding
                    FROM {self.schema}.{self.table_name} c
                    JOIN public.cve_cpe cp ON cp.cve_id = c.cve_id
                    WHERE cp.cpe_base = $1
                      AND cp.vulnerable = TRUE
                      {_SQL_EXCLUDE_REJECTED_DEFERRED}
                    ORDER BY c.cvss_score DESC, c.threat_level DESC
                """, cpe_base)
                seen_ids = {row['cve_id'] for row in exact_results}
                wildcard_results = [r for r in base_rows if r['cve_id'] not in seen_ids]

            range_results = []
            if input_version or version_val == '-':
                range_query = f"""
                    SELECT DISTINCT
                        cp.cpe_base,
                        c.cve_id, c.cvss_score, c.threat_level, c.cve_status,
                        c.published, c.last_modified, c.source_name, c.first_seen, c.last_fetched,
                        c.expires_at, c.is_kev, c.description, c.cvss_v3_vector_string, c.epss_score,
                        c.details, c.configurations,
                        cp.vulnerable, cp.version_start_including, cp.version_start_excluding,
                        cp.version_end_including, cp.version_end_excluding
                    FROM {self.schema}.{self.table_name} c
                    JOIN public.cve_cpe cp ON cp.cve_id = c.cve_id
                    WHERE cp.cpe_base = $1
                      AND cp.vulnerable = TRUE
                      {_SQL_EXCLUDE_REJECTED_DEFERRED}
                      AND c.cve_id != ALL($2::text[])
                      AND (
                            cp.version_start_including IS NOT NULL OR
                            cp.version_start_excluding IS NOT NULL OR
                            cp.version_end_including   IS NOT NULL OR
                            cp.version_end_excluding   IS NOT NULL
                          )
                    ORDER BY c.cvss_score DESC, c.threat_level DESC
                """
                candidates = await connection.fetch(
                    range_query, cpe_base, list(exact_cve_ids)
                )
                for row in candidates:
                    if input_version:
                        if self._version_in_range(
                            input_version,
                            row['version_start_including'],
                            row['version_start_excluding'],
                            row['version_end_including'],
                            row['version_end_excluding'],
                        ):
                            range_results.append(row)
                    else:
                        # version '-' (N/A): product name encodes the version,
                        # include all range-based CVEs for this base
                        range_results.append(row)

            all_rows = []
            for r in exact_results:
                d = dict(r); d['match_type'] = 'exact'; all_rows.append(d)
            for r in wildcard_results:
                d = dict(r); d['match_type'] = 'wildcard'; all_rows.append(d)
            for r in range_results:
                d = dict(r); d['match_type'] = 'range'; all_rows.append(d)
            cve_list = [self._hydrate_row(r) for r in all_rows]
            logger.debug(
                f"Found {len(cve_list)} CVEs matching CPE: {cpe_string} "
                f"(exact={len(exact_results)}, wildcard={len(wildcard_results)}, range={len(range_results)})"
            )
            return cve_list

        except Exception as e:
            logger.error(f"Error finding CVEs by CPE {cpe_string} in database: {e}")
            return []
        finally:
            if connection and connection_id:
                await self._release_connection(connection, connection_id)

    async def find_by_cpe_batch(self, cpe_strings: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Bulk CVE lookup for N CPE strings — two DB round-trips regardless of N.

        Returns {cpe_string: [CVE dicts]}.
        """
        if not self.db_pool:
            raise RuntimeError("Database pool not available")

        results: Dict[str, List[Dict[str, Any]]] = {cpe: [] for cpe in cpe_strings}
        cpe_metas = {}
        for cpe in cpe_strings:
            parts = cpe.split(':')
            cpe_metas[cpe] = {
                'base':    ':'.join(parts[:5]) if len(parts) >= 5 else cpe,
                'version': self._parse_cpe_version(cpe),
                'update':  parts[6] if len(parts) > 6 else '*',
                'version_raw': parts[5] if len(parts) > 5 else '*',
            }

        connection = None
        connection_id = None
        try:
            connection, connection_id = await self._acquire_connection_with_retry()

            # CPE dictionary gate: check each versioned CPE against the dictionary,
            # matching all non-wildcard components exactly (NVD literal search behaviour).
            versioned_candidates = {cpe: m for cpe, m in cpe_metas.items()
                                    if m['version_raw'] not in ('*', '')}
            if versioned_candidates:
                unique_pairs   = list({(m['base'], m['version_raw']) for m in versioned_candidates.values()})
                unique_bases   = [p[0] for p in unique_pairs]
                unique_versions = [p[1] for p in unique_pairs]
                dict_rows = await connection.fetch(
                    """
                    SELECT cpe_name, cpe_base, COALESCE(version, '-') AS version
                    FROM public.cpe_dictionary
                    WHERE (cpe_base, COALESCE(version, '-')) IN (
                        SELECT b, v FROM UNNEST($1::text[], $2::text[]) AS t(b, v)
                    )
                    """,
                    unique_bases, unique_versions,
                )
                # Group stored dictionary entries by (base, version) for fast lookup
                dict_by_base_ver: Dict[tuple, list] = {}
                for row in dict_rows:
                    dict_by_base_ver.setdefault((row['cpe_base'], row['version']), []).append(
                        row['cpe_name'].split(':')
                    )
                for cpe, m in list(versioned_candidates.items()):
                    input_parts = cpe.split(':')
                    candidates_for_pair = dict_by_base_ver.get((m['base'], m['version_raw']), [])
                    if not any(self._cpe_dict_match(input_parts, sp) for sp in candidates_for_pair):
                        logger.debug(f"CPE not in dictionary, skipping: {cpe}")
                        results.pop(cpe, None)
                        cpe_metas.pop(cpe, None)

            if not cpe_metas:
                return results

            all_pending: List[tuple] = []
            # Pass 1 — point-CPE match: fetch all no-bounds CPE rows for versioned bases,
            # then filter in Python on version and update (wildcard-aware).
            seen_by_cpe: Dict[str, set] = {}
            versioned_metas = {cpe: m for cpe, m in cpe_metas.items()
                               if m['version_raw'] not in ('*', '')}
            if versioned_metas:
                unique_point_bases    = list({m['base']        for m in versioned_metas.values()})
                unique_point_versions = list({m['version_raw'] for m in versioned_metas.values()})
                point_rows = await connection.fetch(f"""
                    SELECT DISTINCT
                        cp.cpe_base,
                        cp.cpe_string AS matched_cpe,
                        split_part(cp.cpe_string, ':', 6) AS stored_version,
                        split_part(cp.cpe_string, ':', 7) AS stored_update,
                        c.cve_id, c.cvss_score, c.threat_level, c.cve_status,
                        c.published, c.last_modified, c.source_name, c.first_seen, c.last_fetched,
                        c.expires_at, c.is_kev, c.description, c.cvss_v3_vector_string, c.epss_score,
                        c.details, c.configurations,
                        cp.vulnerable, cp.version_start_including, cp.version_start_excluding,
                        cp.version_end_including, cp.version_end_excluding
                    FROM {self.schema}.{self.table_name} c
                    JOIN public.cve_cpe cp ON cp.cve_id = c.cve_id
                    WHERE cp.cpe_base = ANY($1::text[])
                      AND split_part(cp.cpe_string, ':', 6) = ANY($2::text[])
                      AND cp.version_start_including IS NULL
                      AND cp.version_start_excluding IS NULL
                      AND cp.version_end_including   IS NULL
                      AND cp.version_end_excluding   IS NULL
                      AND cp.vulnerable = TRUE
                      {_SQL_EXCLUDE_REJECTED_DEFERRED}
                    ORDER BY c.cvss_score DESC, c.threat_level DESC
                """, unique_point_bases, unique_point_versions)

                for row in point_rows:
                    stored_ver = row['stored_version']
                    stored_upd = row['stored_update']
                    for cpe, meta in versioned_metas.items():
                        if meta['base'] != row['cpe_base']:
                            continue
                        if stored_ver != meta['version_raw']:
                            continue
                        inp_upd = meta['update']
                        if inp_upd != '*' and stored_upd != inp_upd and stored_upd != '*':
                            continue
                        seen = seen_by_cpe.setdefault(cpe, set())
                        if row['cve_id'] not in seen:
                            seen.add(row['cve_id'])
                            row_dict = dict(row)
                            row_dict['match_type'] = 'exact'
                            all_pending.append((cpe, row_dict))

            wildcard_version = {
                cpe: m for cpe, m in cpe_metas.items()
                if cpe.split(':')[5] == '*' if len(cpe.split(':')) > 5
            }
            if wildcard_version:
                unique_wc_bases = list({m['base'] for m in wildcard_version.values()})
                wc_rows = await connection.fetch(f"""
                    SELECT DISTINCT cp.cpe_base,
                        c.cve_id, c.cvss_score, c.threat_level, c.cve_status,
                        c.published, c.last_modified, c.source_name, c.first_seen, c.last_fetched,
                        c.expires_at, c.is_kev, c.description, c.cvss_v3_vector_string, c.epss_score,
                        c.details, c.configurations,
                        cp.vulnerable, cp.version_start_including, cp.version_start_excluding,
                        cp.version_end_including, cp.version_end_excluding
                    FROM {self.schema}.{self.table_name} c
                    JOIN public.cve_cpe cp ON cp.cve_id = c.cve_id
                    WHERE cp.cpe_base = ANY($1::text[])
                      AND cp.vulnerable = TRUE
                      {_SQL_EXCLUDE_REJECTED_DEFERRED}
                    ORDER BY c.cvss_score DESC, c.threat_level DESC
                """, unique_wc_bases)

                wc_rows_by_base: Dict[str, list] = {}
                for row in wc_rows:
                    wc_rows_by_base.setdefault(row['cpe_base'], []).append(row)

                for cpe, meta in wildcard_version.items():
                    seen = seen_by_cpe.get(cpe, set())
                    for row in wc_rows_by_base.get(meta['base'], []):
                        if row['cve_id'] not in seen:
                            seen.add(row['cve_id'])
                            row_dict = dict(row)
                            row_dict['match_type'] = 'wildcard'
                            all_pending.append((cpe, row_dict))

            versioned = {cpe: m for cpe, m in cpe_metas.items()
                        if m['version'] or m['version_raw'] == '-'}
            if versioned:
                unique_bases = list({m['base'] for m in versioned.values()})
                range_rows = await connection.fetch(f"""
                    SELECT DISTINCT cp.cpe_base,
                        c.cve_id, c.cvss_score, c.threat_level, c.cve_status,
                        c.published, c.last_modified, c.source_name, c.first_seen, c.last_fetched,
                        c.expires_at, c.is_kev, c.description, c.cvss_v3_vector_string, c.epss_score,
                        c.details, c.configurations,
                        cp.vulnerable, cp.version_start_including, cp.version_start_excluding,
                        cp.version_end_including,   cp.version_end_excluding
                    FROM {self.schema}.{self.table_name} c
                    JOIN public.cve_cpe cp ON cp.cve_id = c.cve_id
                    WHERE cp.cpe_base = ANY($1::text[])
                      AND cp.vulnerable = TRUE
                      {_SQL_EXCLUDE_REJECTED_DEFERRED}
                      AND (
                            cp.version_start_including IS NOT NULL OR
                            cp.version_start_excluding IS NOT NULL OR
                            cp.version_end_including   IS NOT NULL OR
                            cp.version_end_excluding   IS NOT NULL
                          )
                    ORDER BY c.cvss_score DESC, c.threat_level DESC
                """, unique_bases)

                candidates_by_base: Dict[str, list] = {}
                for row in range_rows:
                    candidates_by_base.setdefault(row['cpe_base'], []).append(row)

                for cpe, meta in versioned.items():
                    seen = seen_by_cpe.get(cpe, set())
                    for row in candidates_by_base.get(meta['base'], []):
                        if row['cve_id'] in seen:
                            continue
                        if meta['version']:
                            if self._version_in_range(
                                meta['version'],
                                row['version_start_including'],
                                row['version_start_excluding'],
                                row['version_end_including'],
                                row['version_end_excluding'],
                            ):
                                seen.add(row['cve_id'])
                                row_dict = dict(row)
                                row_dict['match_type'] = 'range'
                                all_pending.append((cpe, row_dict))
                        else:
                            # version '-' (N/A): product name encodes the version,
                            # include all range-based CVEs for this base
                            seen.add(row['cve_id'])
                            row_dict = dict(row)
                            row_dict['match_type'] = 'range'
                            all_pending.append((cpe, row_dict))

            for cpe, row_dict in all_pending:
                results[cpe].append(self._hydrate_row(row_dict))

            logger.debug(
                f"find_by_cpe_batch: {len(cpe_strings)} CPEs → "
                f"{sum(len(v) for v in results.values())} CVE matches"
            )
            return results

        except Exception as e:
            logger.error(f"Error in find_by_cpe_batch: {e}")
            return results
        finally:
            if connection and connection_id:
                await self._release_connection(connection, connection_id)
    
    async def save_with_cpe_mappings(self, cve_data: CVEData) -> bool:
        """Save CVE to cve_cache and persist all its cpeMatch entries to cve_cpe."""
        saved = await self.save(cve_data)
        if not saved:
            return False

        configurations = getattr(cve_data, 'configurations', None) or []
        if not configurations:
            return True

        rows = []
        seen = set()
        for config in configurations:
            for node in config.get('nodes', []):
                nodes_to_process = [node] + node.get('nodes', [])
                for n in nodes_to_process:
                    for cpe_match in n.get('cpeMatch', []):
                        criteria = cpe_match.get('criteria')
                        if not criteria:
                            continue
                        parts = criteria.split(':')
                        cpe_base = ':'.join(parts[:5]) if len(parts) >= 5 else criteria
                        key = (
                            criteria,
                            cpe_match.get('versionStartIncluding'),
                            cpe_match.get('versionStartExcluding'),
                            cpe_match.get('versionEndIncluding'),
                            cpe_match.get('versionEndExcluding'),
                        )
                        if key in seen:
                            continue
                        seen.add(key)
                        rows.append((
                            str(cve_data.cve_id),
                            criteria,
                            cpe_base,
                            bool(cpe_match.get('vulnerable', True)),
                            cpe_match.get('versionStartIncluding'),
                            cpe_match.get('versionStartExcluding'),
                            cpe_match.get('versionEndIncluding'),
                            cpe_match.get('versionEndExcluding'),
                        ))

        if not rows:
            return True

        connection = None
        connection_id = None
        try:
            connection, connection_id = await self._acquire_connection_with_retry()
            await connection.executemany("""
                INSERT INTO public.cve_cpe (
                    cve_id, cpe_string, cpe_base, vulnerable,
                    version_start_including, version_start_excluding,
                    version_end_including, version_end_excluding
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (cve_id, cpe_string) DO UPDATE SET
                    cpe_base = EXCLUDED.cpe_base,
                    vulnerable = EXCLUDED.vulnerable,
                    version_start_including = EXCLUDED.version_start_including,
                    version_start_excluding = EXCLUDED.version_start_excluding,
                    version_end_including = EXCLUDED.version_end_including,
                    version_end_excluding = EXCLUDED.version_end_excluding
            """, rows)
            logger.debug(f"Saved {len(rows)} CPE mappings for {cve_data.cve_id}")
            return True
        except Exception as e:
            logger.error(f"Error saving CPE mappings for {cve_data.cve_id}: {e}")
            return False
        finally:
            if connection and connection_id:
                await self._release_connection(connection, connection_id)

    async def save(self, cve_data: CVEData) -> bool:
        """Save or update CVE data in database"""
        if not self.db_pool:
            raise RuntimeError("Database pool not available")
        
        connection = None
        connection_id = None
        try:
            connection, connection_id = await self._acquire_connection_with_retry()
            
            db_dict = cve_data.to_db_dict()
            
            details_bytes = None
            if db_dict.get('raw_data'):
                try:
                    raw_data_json = json.dumps(db_dict['raw_data']).encode('utf-8')
                    details_bytes = self.zstd_compressor.compress(raw_data_json)
                except Exception as e:
                    logger.warning(f"Failed to compress details for CVE {db_dict['id']}: {e}")
            
            cvss_score_normalized = float(db_dict['score']) if db_dict.get('score') else None
            threat_level = cve_data.threat_level
            is_kev = bool(db_dict.get('cisa_exploit_add') or db_dict.get('cisa_vulnerability_name'))
            
            query = f"""
                INSERT INTO {self.schema}.{self.table_name} (
                    cve_id, configurations, cvss_score, threat_level, cve_status, published, last_modified,
                    source_name, first_seen, last_fetched, details, expires_at, is_kev, cvss_v3_vector_string,
                    description, epss_score
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
                )
                ON CONFLICT (cve_id) DO UPDATE SET
                    configurations = EXCLUDED.configurations,
                    cvss_score = CASE
                        WHEN EXCLUDED.cvss_score IS NOT NULL AND EXCLUDED.cvss_score > 0
                        THEN EXCLUDED.cvss_score
                        ELSE COALESCE({self.schema}.{self.table_name}.cvss_score, EXCLUDED.cvss_score)
                    END,
                    threat_level = CASE
                        WHEN EXCLUDED.cvss_score IS NOT NULL AND EXCLUDED.cvss_score > 0
                        THEN EXCLUDED.threat_level
                        ELSE COALESCE({self.schema}.{self.table_name}.threat_level, EXCLUDED.threat_level)
                    END,
                    cve_status = EXCLUDED.cve_status,
                    published = EXCLUDED.published,
                    last_modified = EXCLUDED.last_modified,
                    source_name = EXCLUDED.source_name,
                    first_seen = EXCLUDED.first_seen,
                    last_fetched = EXCLUDED.last_fetched,
                    details = COALESCE(EXCLUDED.details, {self.schema}.{self.table_name}.details),
                    expires_at = EXCLUDED.expires_at,
                    is_kev = EXCLUDED.is_kev,
                    cvss_v3_vector_string = COALESCE(EXCLUDED.cvss_v3_vector_string, {self.schema}.{self.table_name}.cvss_v3_vector_string),
                    description = COALESCE(EXCLUDED.description, {self.schema}.{self.table_name}.description),
                    epss_score = COALESCE(EXCLUDED.epss_score, {self.schema}.{self.table_name}.epss_score)
            """

            await connection.execute(
                query,
                db_dict['id'],
                json.dumps(db_dict['configurations']) if db_dict.get('configurations') else None,
                cvss_score_normalized,
                threat_level,
                db_dict.get('vuln_status'),
                db_dict['published'],
                db_dict['last_modified'],
                db_dict.get('source_identifier'),
                db_dict.get('first_fetched'),
                db_dict.get('last_fetched'),
                details_bytes,
                db_dict.get('expires_at'),
                is_kev,
                cve_data.cvss_v3_vector_string,
                db_dict.get('description_en'),
                cve_data.epss_score,
            )
            
            logger.debug(f"Saved CVE data: {db_dict['id']}")
            return True
                
        except Exception as e:
            logger.error(f"Error saving CVE {cve_data.cve_id} to database: {e}", exc_info=True)
            return False
        finally:
            if connection and connection_id:
                await self._release_connection(connection, connection_id)
    
    async def save_queried_cpe_mappings(self, queried_cpe: str, cve_ids: List[str]) -> None:
        """
        Insert a direct cpe_string → cve_id mapping for the exact CPE string that was
        queried. This ensures future lookups for the same CPE string hit the DB (exact
        match) instead of falling back to the NVD API every time.
        """
        if not cve_ids or not self.db_pool:
            return
        parts = queried_cpe.split(':')
        cpe_base = ':'.join(parts[:5]) if len(parts) >= 5 else queried_cpe
        rows = [(cve_id, queried_cpe, cpe_base, True, None, None, None, None) for cve_id in cve_ids]
        connection = None
        connection_id = None
        try:
            connection, connection_id = await self._acquire_connection_with_retry()
            await connection.executemany("""
                INSERT INTO public.cve_cpe (
                    cve_id, cpe_string, cpe_base, vulnerable,
                    version_start_including, version_start_excluding,
                    version_end_including, version_end_excluding
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT DO NOTHING
            """, rows)
            logger.debug(f"Saved {len(rows)} queried-CPE mappings for {queried_cpe}")
        except Exception as e:
            logger.error(f"Error saving queried CPE mappings for {queried_cpe}: {e}")
        finally:
            if connection and connection_id:
                await self._release_connection(connection, connection_id)

    async def find_by_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Not implemented for CVE repository"""
        raise NotImplementedError("CVE repository doesn't handle IP lookups")
    
    async def find_by_ips(self, ip_addresses: List[str]) -> List[Dict[str, Any]]:
        """Not implemented for CVE repository"""
        raise NotImplementedError("CVE repository doesn't handle IP lookups")
    
    async def find_by_hash(self, hash_value: str, hash_type: str = "sha256") -> Optional[Dict[str, Any]]:
        """Not implemented for CVE repository"""
        raise NotImplementedError("CVE repository doesn't handle hash lookups")
    
    async def find_by_hashes(self, hash_list: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """Not implemented for CVE repository"""
        raise NotImplementedError("CVE repository doesn't handle hash lookups")
    
    async def save_batch(self, threat_data_list: List[Dict[str, Any]]) -> bool:
        """Not implemented for CVE repository"""
        raise NotImplementedError("CVE repository doesn't support batch save")
    
    async def health_check(self) -> bool:
        """Check database connectivity"""
        try:
            connection, connection_id = await self._get_connection()
            if connection:
                await connection.fetchval("SELECT 1")
                await self._release_connection(connection, connection_id)
                return True
            return False
        except Exception as e:
            logger.error(f"CVE database health check failed: {e}")
            return False
    
    async def close(self) -> None:
        """Close database connections"""
        try:
            if self.db_pool:
                await self.db_pool.close()
                logger.info("CVE PostgreSQL pool closed")
        except Exception as e:
            logger.error(f"Error closing CVE PostgreSQL pool: {e}")
