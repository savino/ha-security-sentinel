# Security Sentinel — Technical & Functional Specification

> **Version:** 0.2.0 | **Status:** Draft | **Last Updated:** 2026-02-25

---

## 1. Overview

**Security Sentinel** is a custom Home Assistant integration designed to:

- Monitor Home Assistant logs and the internal event bus for unauthorized access attempts
- Enrich detected events with IP geolocation and network intelligence data
- Trigger configurable actions (persistent notifications, mobile push, SMTP email)
- Expose sensor entities with up-to-date security metrics
- Provide a dedicated Lovelace dashboard card (`security-sentinel-card`) for visual monitoring

The integration is fully configurable via the HA UI (Config Flow) and is HACS-compatible.

---

## 2. Goals and Non-Goals

### 2.1 Goals

- Parse HA auth events and log files for security-relevant patterns
- Detect: failed login attempts, brute-force patterns, new/unknown devices, suspicious service calls, external IP access
- Enrich events with IP geolocation (country, city, ASN/ISP) from free/open APIs
- Fire HA bus events and persistent notifications automatically
- Send configurable email alerts via SMTP or HA `notify.*` services
- Expose sensor entities (`sensor.security_sentinel_*`) with rich attributes
- Provide a custom Lovelace card with an expandable event timeline
- Full UI-based configuration (no YAML required)
- HACS-compatible packaging

### 2.2 Non-Goals (current phase)

- Direct network packet inspection or deep packet analysis
- Active IP blocking or firewall rule management (Phase 2)
- Replacement of dedicated IDS/IPS solutions
- Multi-instance / remote HA support (Phase 3)

---

## 3. Architecture

### 3.1 Component Map

```
ha-security-sentinel/
├── custom_components/
│   └── security_sentinel/
│       ├── __init__.py          # Integration entry point
│       ├── manifest.json        # HACS/HA manifest
│       ├── config_flow.py       # UI configuration wizard
│       ├── coordinator.py       # DataUpdateCoordinator
│       ├── const.py             # Constants and defaults
│       ├── sensor.py            # Sensor entities
│       ├── event_monitor.py     # HA event bus subscription + log parsing
│       ├── geo_lookup.py        # IP geolocation with caching and fallback
│       ├── actions.py           # Notification and email dispatcher
│       ├── store.py             # Persistent event storage
│       ├── strings.json         # UI strings
│       └── frontend/
│           └── security-sentinel-card.js  # Custom Lovelace card (auto-copied to /config/www)
├── .github/
│   └── workflows/
│       └── ci.yml              # GitHub Actions CI
├── hacs.json
├── README.md
└── SPEC.md                     # This document
```

### 3.2 Module Descriptions

| Module | Responsibility |
|---|---|
| `__init__.py` | Entry point: wires up coordinator, monitor, store, and platforms |
| `coordinator.py` | `DataUpdateCoordinator` subclass; aggregates metrics, calls geo lookup and action dispatcher |
| `config_flow.py` | Multi-step UI configuration and options flow |
| `event_monitor.py` | Subscribes to HA event bus; implements brute-force detection state machine |
| `geo_lookup.py` | Async IP enrichment with in-memory TTL cache and API fallback |
| `actions.py` | Dispatches persistent notifications, mobile push, and SMTP email |
| `store.py` | JSON-backed persistent storage via `homeassistant.helpers.storage.Store` |
| `sensor.py` | Three sensor entities exposing metrics and event attributes |

---

## 4. Detected Event Types

| Event ID | Source | Description | Default Severity |
|---|---|---|---|
| `AUTH_FAILED` | HA auth / HTTP log | Failed login attempt from an IP | medium |
| `BRUTE_FORCE` | Pattern engine | ≥ N `AUTH_FAILED` within T seconds from same IP | critical |
| `NEW_DEVICE` | `device_registry` / `mobile_app` | First-seen unknown device | low |
| `SUSPICIOUS_SERVICE` | Event bus `call_service` | Sensitive service invoked from unexpected context | high |
| `EXTERNAL_ACCESS` | `http` component | Request received from an external (non-LAN) IP | low |

### 4.1 Brute-Force Detection Logic

```
For each AUTH_FAILED(ip):
    timestamps[ip] = [ts for ts in timestamps[ip] if now - ts <= window]
    timestamps[ip].append(now)
    if len(timestamps[ip]) >= threshold:
        fire BRUTE_FORCE(ip)
        clear timestamps[ip]
```

Configurable parameters: `failed_login_threshold` (default 5), `brute_force_window` (default 60s).

---

## 5. IP Enrichment

### 5.1 Data Flow

```
Raw IP
  └──► Private range check ──► skip (return "Local")
  └──► Cache hit (TTL 1h)  ──► return cached result
  └──► ip-api.com/json/{ip}  ──► parse & cache
         └── on failure ──► ipinfo.io/{ip}/json ──► parse & cache
                              └── on failure ──► return {"country": "Unknown"}
```

### 5.2 Enriched Fields

| Field | Source | Description |
|---|---|---|
| `country` | Both APIs | Full country name |
| `country_code` | Both APIs | ISO 3166-1 alpha-2 |
| `region` | Both APIs | Region / state |
| `city` | Both APIs | City name |
| `org` | Both APIs | ISP name or ASN string |
| `isp` | ip-api.com | Internet Service Provider name |
| `lat` / `lon` | Both APIs | Geographic coordinates |
| `timezone` | Both APIs | Timezone identifier |

### 5.3 Rate Limiting & Caching

- **ip-api.com**: Free tier, no API key required, 45 req/min limit
- **ipinfo.io**: Free tier with optional API key (50k req/month)
- In-memory LRU-style cache with 1-hour TTL prevents redundant calls

---

## 6. Sensor Entities

| Entity ID | State | Unit | State Class |
|---|---|---|---|
| `sensor.security_sentinel_failed_logins` | integer count (24h) | attempts | measurement |
| `sensor.security_sentinel_last_event` | event type string | — | — |
| `sensor.security_sentinel_threat_level` | low / medium / high / critical | — | — |

### 6.1 Sensor Attributes

**`sensor.security_sentinel_failed_logins`**
```json
{
  "component_version": "0.2.0",
  "last_ip": "1.2.3.4",
  "last_time": "2026-02-20T10:00:00+00:00",
  "recent_events": [ ... ]
}
```

**`sensor.security_sentinel_last_event`**
```json
{
  "component_version": "0.2.0",
  "ip": "1.2.3.4",
  "geo": { "country": "Russia", "city": "Moscow", "org": "AS12345 Rostelecom" },
  "detail": "Failed login attempt #3",
  "severity": "medium",
  "timestamp": "2026-02-20T10:00:00+00:00"
}
```

**`sensor.security_sentinel_threat_level`**
```json
{
  "component_version": "0.2.0",
  "total_events_loaded": 42,
  "recent_events": [ ... ]
}
```

### 6.2 Threat Score Calculation

| Severity | Score per event |
|---|---|
| low | +1 |
| medium | +2 |
| high | +5 |
| critical | +10 |

| Total Score | Threat Level |
|---|---|
| 0 – 3 | low |
| 4 – 9 | medium |
| 10 – 19 | high |
| ≥ 20 | critical |

---

## 7. Actions & Notifications

### 7.1 Action Matrix

| Action | Minimum Severity | Configurable | Notes |
|---|---|---|---|
| Persistent notification | all | no | Always fires |
| HA bus event (`security_sentinel_event`) | all | no | Usable in automations |
| Mobile push (`notify.*`) | high | yes | Requires `notify_service` config |
| SMTP email | high | yes | Requires SMTP config |

### 7.2 Email Alert Format

HTML email with table layout:
- Event type and severity badge
- Source IP address
- Geolocation: country, city, ISP/ASN
- Event detail text
- Timestamp

---

## 8. Configuration (Config Flow)

### 8.1 Setup Parameters

| Key | Type | Default | Description |
|---|---|---|---|
| `scan_interval` | int | 60 | Coordinator update interval in seconds |
| `failed_login_threshold` | int | 5 | AUTH_FAILED count to trigger BRUTE_FORCE |
| `brute_force_window` | int | 60 | Time window in seconds for brute-force check |
| `notify_service` | string | `persistent_notification` | HA notify service (e.g. `notify.mobile_app_myphone`) |
| `email_recipient` | string | — | SMTP alert recipient address |
| `smtp_host` | string | — | SMTP server hostname |
| `smtp_port` | int | 587 | SMTP port (STARTTLS) |
| `smtp_username` | string | — | SMTP auth username |
| `smtp_password` | string | — | SMTP auth password (stored encrypted) |
| `geo_api_key` | string | — | ipinfo.io API token (optional) |

---

## 9. Lovelace Card (`security-sentinel-card`)

### 9.1 Card Configuration Options

| Option | Type | Default | Description |
|---|---|---|---|
| `title` | string | `Security Sentinel` | Card title |
| `max_events` | int | 10 | Max events to display |
| `severity_filter` | list\<string\> | [] | Only show these severity levels |

### 9.2 Card Features

- Summary stats row: failed logins (24h) + recent event count
- Color-coded threat level badge (green → purple)
- Per-event expandable row with:
  - Severity dot indicator
  - Event type + source IP with country flag emoji
  - Full geolocation detail (country, city, ISP, region, timezone, coordinates)
  - Human-readable timestamp

### 9.3 Card Installation (manual)

Repository-type clarification:

- HACS **Dashboard/Plugin** repositories place frontend files under `www/community` and are usually referenced via `/hacsfiles/...` or `/local/...`.
- Security Sentinel is a HACS **Integration** repository, so its Lovelace resource must still be added in Dashboard Resources.

Card JS file path in HA config directory:

```
/config/www/security-sentinel-card.js
```

Served URL used by Lovelace resources:

```yaml
# configuration.yaml or resources section in Lovelace
lovelace:
  resources:
    - url: /local/security-sentinel-card.js
      type: module
```

Note: after the integration is set up, startup copies the bundled card automatically to `/config/www/security-sentinel-card.js`.

Recommended sequence:

1. Install/update integration
2. Restart HA
3. Add/setup Security Sentinel integration
4. Add resource URL `/local/security-sentinel-card.js`

Then in dashboard YAML:
```yaml
type: custom:security-sentinel-card
title: Security Sentinel
max_events: 15
severity_filter:
  - high
  - critical
```

---

## 10. Data Flow Diagram

```
┌─────────────────────────────────────────────────────┐
│                  Home Assistant Core                │
│                                                     │
│  HA Event Bus ──────────┐                           │
│  (auth, services, etc.) │                           │
│                         ▼                           │
│               ┌──────────────────┐                 │
│               │  EventMonitor    │                 │
│               │  (brute-force    │                 │
│               │   state machine) │                 │
│               └────────┬─────────┘                 │
│                        │ process_event()            │
│                        ▼                           │
│               ┌──────────────────┐                 │
│               │   Coordinator    │                 │
│               │  (orchestrates)  │                 │
│               └──┬──────────┬────┘                 │
│                  │          │                       │
│          ┌───────▼─┐   ┌────▼──────────┐           │
│          │GeoLookup│   │ActionDispatch │           │
│          │(ip-api  │   │(notify/email/ │           │
│          │ipinfo)  │   │ bus event)    │           │
│          └───────┬─┘   └───────────────┘           │
│                  │                                  │
│          ┌───────▼──────┐    ┌────────────────┐    │
│          │ EventStore   │───►│ Sensor Entities │   │
│          │ (persistent) │    │ (3 sensors)     │   │
│          └──────────────┘    └────────┬────────┘   │
│                                       │             │
│                                       ▼             │
│                              ┌────────────────┐    │
│                              │ Lovelace Card  │    │
│                              │ (timeline UI)  │    │
│                              └────────────────┘    │
└─────────────────────────────────────────────────────┘
```

---

## 11. Technology Stack

| Layer | Technology / Version |
|---|---|
| Integration language | Python 3.11+ |
| Minimum HA version | 2024.1.0 |
| Persistent storage | `homeassistant.helpers.storage.Store` (JSON) |
| HTTP client | `aiohttp` (built into HA) |
| Lovelace card | Lit 2.x, vanilla JS (ES module) |
| CI | GitHub Actions + `home-assistant/actions/hassfest` |
| Packaging | HACS-compatible (`hacs.json` + manifest) |

---

## 12. Security Considerations

- SMTP password is stored via HA config entry data (HA encrypts secrets at rest)
- IP lookups are made to third-party APIs; no HA credentials are ever sent externally
- Geo API calls are rate-limited and cached to prevent data leakage via excessive lookups
- The integration listens to HA internal events only; it does not open any network socket itself
- No external agent or script is executed; all actions go through HA service calls

---

## 13. Roadmap

### Phase 1 — Current
- [x] Core event monitoring (AUTH_FAILED, BRUTE_FORCE)
- [x] IP geolocation enrichment with caching and fallback
- [x] Persistent notification + SMTP email alerts
- [x] Three sensor entities with rich attributes
- [x] Lovelace card v1 (timeline, expandable rows, geo details)
- [x] HACS-compatible manifest

### Phase 2
- [ ] AbuseIPDB threat intelligence integration
- [ ] Geo-based suspicious login detection (impossible travel)
- [ ] SIEM-compatible JSON event export (Splunk, Elastic)
- [ ] Interactive minimap on Lovelace card
- [ ] Active response: suggest or apply IP-based firewall rules

### Phase 3
- [ ] Webhook integration (Slack, PagerDuty, Teams)
- [ ] Multi-instance / HA Cloud remote support
- [ ] HA Repairs integration for actionable security advisories
- [ ] Machine-learning anomaly detection (baseline + deviation)
