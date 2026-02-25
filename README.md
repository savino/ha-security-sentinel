# 🛡️ Security Sentinel for Home Assistant

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/integration)
[![HA Version](https://img.shields.io/badge/Home%20Assistant-2024.1+-blue)](https://www.home-assistant.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Security Sentinel is a custom Home Assistant integration that monitors logs and the internal event bus for unauthorized access attempts, enriches security events with IP geolocation data, triggers configurable alerts (push notifications, email), and provides a dedicated Lovelace dashboard card.

## ✨ Features

- 🔍 **Real-time monitoring** of HA auth events and log patterns
- 🚨 **Brute-force detection** with configurable thresholds and time windows
- 🌍 **IP Geolocation enrichment** — country, city, ISP/ASN via ip-api.com / ipinfo.io
- 📬 **Multi-channel alerts** — persistent notifications, mobile push, SMTP email
- 📊 **Custom Lovelace card** — color-coded timeline with expandable event details and country flags
- 🔌 **HACS-compatible** — install and configure entirely via the UI
- 💾 **Persistent storage** — event history survives HA restarts

## 🏗️ Architecture

See [SPEC.md](SPEC.md) for the full technical and functional specification including architecture diagrams, data flows, and the complete roadmap.

## 📦 Installation

### Via HACS (recommended)
1. Add this repository as a custom HACS integration repository
2. Search for **Security Sentinel**
3. Install and restart Home Assistant

### Manual
Copy the `custom_components/security_sentinel/` directory into your HA `config/custom_components/` folder, then restart.

## ⚙️ Configuration

1. Go to **Settings → Devices & Services → Add Integration**
2. Search for **Security Sentinel**
3. Follow the configuration wizard

| Key | Default | Description |
|---|---|---|
| `scan_interval` | 60s | Coordinator refresh interval |
| `failed_login_threshold` | 5 | Attempts before brute-force alert |
| `brute_force_window` | 60s | Detection window |
| `notify_service` | `persistent_notification` | HA notify service |
| `email_recipient` | — | SMTP alert target |
| `geo_api_key` | — | ipinfo.io token (optional) |

## 📊 Lovelace Card

Important distinction (from HACS docs):

- **Dashboard/Plugin repositories** (for example `scheduler-card`, `simple-weather-card`, `modern-circular-gauge`) are installed by HACS under `www/community` and typically use `/hacsfiles/...` or `/local/...` resource paths.
- **This repository is an Integration repository** (`custom_components/...`). HACS installs backend files only; frontend resource registration is still your responsibility.

For Security Sentinel, the integration setup copies the card file automatically to:

- `/config/www/security-sentinel-card.js` (served by HA as `/local/security-sentinel-card.js`)

### Required steps (Security Sentinel)

1. Install/update the integration and restart Home Assistant.
2. Add Security Sentinel integration in **Settings → Devices & Services** (this triggers the card file copy).
3. Add this dashboard resource in **Settings → Dashboards → Resources** (or YAML):

```yaml
url: /local/security-sentinel-card.js
type: module
```

If the card does not appear, clear browser cache and hard-refresh the dashboard.

---

### Card Configuration Reference

| Option | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | **Required.** Must be `custom:security-sentinel-card` |
| `title` | string | `Security Sentinel` | Card title shown in the header |
| `max_events` | int | `10` | Maximum number of events to display in the timeline |
| `severity_filter` | list\<string\> | `[]` (all) | Only show events matching these severity levels: `low`, `medium`, `high`, `critical` |

---

### Examples

#### Minimal — default settings

The simplest possible configuration; all options fall back to their defaults.

```yaml
type: custom:security-sentinel-card
```

---

#### Standard — custom title and event limit

Show the last 20 events with a descriptive title.

```yaml
type: custom:security-sentinel-card
title: 🛡️ Home Security Monitor
max_events: 20
```

---

#### High-priority only — filter by severity

Only display `high` and `critical` severity events to reduce noise on a security-focused dashboard.

```yaml
type: custom:security-sentinel-card
title: Critical Threats
max_events: 5
severity_filter:
  - high
  - critical
```

---

#### All severity levels — explicit filter

Show every event regardless of severity (equivalent to omitting `severity_filter`).

```yaml
type: custom:security-sentinel-card
title: All Security Events
max_events: 50
severity_filter:
  - low
  - medium
  - high
  - critical
```

---

#### Medium-and-above — balanced view

A common production setup: ignore informational `low` events while still showing `medium` anomalies.

```yaml
type: custom:security-sentinel-card
title: Security Sentinel
max_events: 15
severity_filter:
  - medium
  - high
  - critical
```

---

### Full Dashboard YAML Example

Below is a complete Lovelace dashboard view containing the Security Sentinel card alongside complementary entity cards for at-a-glance security monitoring.

```yaml
title: Security Dashboard
views:
  - title: Security
    icon: mdi:shield-lock
    cards:

      # ── Security Sentinel main card ────────────────────────────
      - type: custom:security-sentinel-card
        title: 🛡️ Security Sentinel
        max_events: 20
        severity_filter:
          - medium
          - high
          - critical

      # ── Sensor summary row ─────────────────────────────────────
      - type: entities
        title: Sensor Summary
        entities:
          - entity: sensor.security_sentinel_failed_logins
            name: Failed Logins (24 h)
          - entity: sensor.security_sentinel_threat_level
            name: Threat Level
          - entity: sensor.security_sentinel_last_event
            name: Last Event Type
          - entity: sensor.security_sentinel_banned_ips
            name: Banned IPs

      # ── Failed logins gauge ────────────────────────────────────
      - type: gauge
        entity: sensor.security_sentinel_failed_logins
        name: Failed Logins
        min: 0
        max: 50
        severity:
          green: 0
          yellow: 5
          red: 20
```

---

### Automation Example

Trigger a mobile notification whenever the threat level reaches `critical`:

```yaml
automation:
  - alias: "Alert on critical threat"
    trigger:
      - platform: state
        entity_id: sensor.security_sentinel_threat_level
        to: "critical"
    action:
      - service: notify.mobile_app_myphone
        data:
          title: "🚨 Security Sentinel"
          message: "Critical threat level detected!"
```

---

### Sensor Attributes (used by the card)

The card reads data directly from four sensor entities created by the integration:

**`sensor.security_sentinel_failed_logins`** — state: integer count of failed logins in the last 24 hours

```json
{
  "component_version": "0.2.0",
  "last_ip": "203.0.113.42",
  "last_time": "2026-02-25T12:34:56+00:00",
  "recent_events": [
    {
      "event_type": "AUTH_FAILED",
      "ip": "203.0.113.42",
      "severity": "medium",
      "timestamp": "2026-02-25T12:34:56+00:00",
      "detail": "Failed login attempt #3",
      "geo": {
        "country": "China",
        "country_code": "CN",
        "city": "Beijing",
        "org": "AS4134 Chinanet",
        "region": "Beijing",
        "timezone": "Asia/Shanghai",
        "lat": 39.9042,
        "lon": 116.4074
      }
    }
  ]
}
```

**`sensor.security_sentinel_threat_level`** — state: `low` | `medium` | `high` | `critical`

```json
{
  "component_version": "0.2.0",
  "total_events_loaded": 42,
  "recent_events": [ "..." ]
}
```

**`sensor.security_sentinel_last_event`** — state: last event type string

```json
{
  "component_version": "0.2.0",
  "ip": "203.0.113.42",
  "geo": { "country": "China", "city": "Beijing", "org": "AS4134 Chinanet" },
  "detail": "Brute-force threshold reached (5 attempts in 60 s)",
  "severity": "critical",
  "timestamp": "2026-02-25T12:35:10+00:00"
}
```

**`sensor.security_sentinel_banned_ips`** — state: integer count of currently banned IPs

```json
{
  "banned_ips": [
    { "ip": "203.0.113.42", "banned_at": "2026-02-25T12:35:10+00:00" }
  ]
}
```

See [SPEC.md § 9](SPEC.md#9-lovelace-card-security-sentinel-card) for full card specification.

## 🗺️ Roadmap

See [SPEC.md § 13](SPEC.md#13-roadmap) for the full roadmap across three phases.

## 📄 License

MIT — see [LICENSE](LICENSE).
