# Sprint Release Versions

Each sprint release is assigned one version number:

| Sprint ID | Release Branch | Production Version |
|-----------|----------------|-------------------|
| Sprint 27 | release-sprint-27 | v1.2.0 |

---

## v1.2.0 - Sprint 27 (2026-01-09)

### Features

- **Memory Optimization**: Implemented comprehensive memory optimization across all services to improve performance and resource utilization
- **CVE Ingestion**: Added CVE correlation and ingestion system with NVD API integration for vulnerability tracking
- **Detection Statistics Display**: Enhanced detection processing with comprehensive statistics display and monitoring
- **Enhanced Database Pooling**: Optimized database connection pooling with configurable min/max sizes
- **Admin API Endpoints**: New administrative endpoints for manual NVD sync triggers

### Bug Fixes

- **Configuration Management**: Fixed configuration loading and environment variable handling

### Technical Improvements

- **API Key Management**: Centralized API key configuration for all external services (OTX, Malware Bazaar, NVD)
- **Rate Limiting**: Implemented proper rate limiting for external API calls to prevent throttling

---

## Hotfixes

| Sprint ID | Release Branch | Production Version |
|-----------|----------------|-------------------|
| _No hotfixes yet_ | - | - |

---
