# GTIC REST API

High-performance IOC threat intelligence caching service built with FastAPI. Provides fast lookups of malicious IOCs (IP addresses and domains) through a 3-tier caching architecture and automatic detection logging.

## Features

- **3-Tier Cache Strategy**: Redis → PostgreSQL → External APIs (AbuseIPDB, VirusTotal)
- **Bulk Processing**: Process up to 100,000 IOCs per request
- **Concurrent Execution**: Async processing with configurable worker pools
- **Smart Expiry**: Threat-based TTL (1 hour to 30 days)
- **Automatic Detection Logging**: Saves threat detections to partitioned database
- **Data Compression**: Zstandard compression for efficient storage

## Architecture

```
Client Request → FastAPI Endpoint
                     ↓
              IOC Checker Service
                     ↓
              IOC Lookup Service
                     ↓
         ┌───────────┴───────────┐
         ↓                       ↓
    Redis Cache          Detection Handler
         ↓                       ↓
   PostgreSQL Cache      Alerts Database
         ↓                       ↓
   External APIs         Detections Database
   (AbuseIPDB/VT)
```

## Prerequisites

- Python 3.12+
- PostgreSQL 12+
- Redis 6+
- AbuseIPDB API Key
- VirusTotal API Key

## Repository Structure

```
gtic/
├── app/                                # REST API
│   ├── main.py                         # FastAPI entry point → IOC check, CVE correlation
│   ├── requirements.txt
│   └── deploy/
│
├── lookup_service/                     # IOC enrichment via external APIs + cache
│   ├── main.py                         # FastAPI entry point → AbuseIPDB, VirusTotal, NVD
│   ├── requirements.txt
│   └── deploy/
│
├── ingestion_services/                 # Scheduled threat feed ingestion
│   ├── run.py                          # OTX pulses + Malware Bazaar → PostgreSQL
│   ├── requirements.txt
│   └── deploy/
│
├── otx_service/                        # OTX-only ingestion
│   ├── run.py                          # OTX pulses → PostgreSQL
│   ├── requirements.txt
│   └── deploy/
│
├── environment/
│   ├── app/.env.example                # vars for GTIC REST API
│   ├── lookup_service/.env.example     # vars for lookup service
│   ├── ingestion_services/.env.example # vars for ingestion services
│   └── otx_service/.env.example        # vars for OTX service
│
├── tests/
│   └── test_api.py
├── test_data/                          # mock IOC payloads (IPs, domains, hashes)
├── version.py                          # shared version info across all services
└── .env                                # runtime config (not committed)
```

## Deployment

```bash
# 1. Clone the repo on the target server
git clone <repo-url> && cd gtic

# 2. Configure environment (merge the relevant templates into one .env)
cat environment/app/.env.example > .env
# then fill in all CHANGE_ME values
nano .env

# 3. Deploy all services (defaults: /opt/gtic, user=gtic, ports 8000/8001/8002)
sudo bash app/deploy/deploy.sh
# or with custom args:
sudo bash app/deploy/deploy.sh /opt/gtic gtic 8000 8001 8002
```

The script syncs the repo, creates a shared venv, installs all dependencies, registers systemd units, and starts all four services.

To update a single service after a code change:
```bash
sudo bash <service>/deploy/update.sh [install_dir]
# e.g. sudo bash lookup_service/deploy/update.sh /opt/gtic
```

## Local Development

```bash
python3 -m venv gtic_env
source gtic_env/bin/activate
pip install -r app/requirements.txt

# Run all services with hot-reload (from repo root)
bash app/deploy/run-test.sh

# Run only the REST API
bash app/deploy/run-dev.sh
```

## Testing

```bash
# Run a manual end-to-end API test against a running instance
python tests/test_api.py

# Sample payloads are in test_data/
# e.g. mock_ips.json, domains_only.json, ips_domains_hashes.json
```

## Configuration

Each service has its own template under `environment/`. Copy the relevant one(s) and merge into a single `.env` at repo root:

```bash
cp environment/app/.env.example .env
# add vars from other services as needed
```

Key variables:

```ini
database_url=postgresql://intelligence_app:PASSWORD@127.0.0.1:5432/intelligence
REDIS_HOST=localhost
REDIS_PORT=6379
ABUSEIPDB_API_KEY=your_key
VIRUSTOTAL_API_KEY=your_key
OTX_API_KEY=your_key
NVD_API_KEY=your_key
LOOKUP_SERVICE_URL=http://localhost:8001
LOG_LEVEL=INFO
```

See `environment/` for per-service variable references.

## API Endpoints

### Check IOCs
```http
POST /api/v1/check-iocs
Content-Type: application/json

{
  "generated_at": "2025-11-11T12:00:00Z",
  "total_ips": 2,
  "total_domains": 1,
  "total_hashes": 0,
  "ip_data": [
    {"ip_address": "8.8.8.8", "log_id": "abc123..."},
    {"ip_address": "1.2.3.4", "log_id": "def456..."}
  ],
  "domains_data": [
    {"domain_name": "malicious.com", "log_id": "ghi789..."}
  ],
  "hashes_data": []
}
```

**Response:**
```json
{
  "processed_at": "2025-11-11T12:00:01Z",
  "total_requested": 3,
  "cache_hits": 2,
  "cache_misses": 1,
  "redis_hits": 1,
  "postgresql_hits": 1,
  "external_api_calls": 1,
  "cached_ips": [...],
  "not_found_ips": [...],
  "cached_domains": [...],
  "not_found_domains": [...]
}
```

### Health Check
```http
GET /health
```

## Database Schema

### Intelligence Cache (`intelligence.ip_cache`)
- Stores threat intelligence data
- Partitioned by IPv4/IPv6
- Compressed JSON details

### Detections (`detections.detections`)
- Logs malicious IOC detections
- Partitioned by IOC type
- Tracks hit counts and patterns

## Logging

Logs are written to `logs/` directory:
- `app.log` - All application logs (rotates at 10MB, keeps 5 backups)
- `error.log` - Error-level logs only

## Performance

- Redis cache hit: ~1-5ms
- PostgreSQL hit: ~10-50ms  
- External API call: ~100-500ms
- Concurrent workers: 20 (configurable)

## Threat score (GTIC) and levels

- **API / cache `threat_score`**: canonical **0–10** scale (0 = no meaningful threat; 1–10 = severity). Values are derived from provider **raw** scores (0–100 style) at ingest/lookup time.
- **`threat_score_detection`** (check-iocs responses): **10–100** for downstream detections storage (`threat_score * 10` when GTIC > 0).
- **Threat levels** (TTL bands) still use the same internal **raw** thresholds before normalization:
  - **0 (NEGATIVE)**: Raw score < 25 — Cached 1 hour
  - **1 (MODERATE)**: Raw score < 50 — Cached 3 days
  - **2 (HIGH)**: Raw score < 75 — Cached 7 days
  - **3 (CRITICAL)**: Raw score ≥ 75 — Cached 30 days



