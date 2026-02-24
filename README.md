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

Then add the card to your dashboard:

```yaml
type: custom:security-sentinel-card
title: Security Sentinel
max_events: 15
```

If the card does not appear, clear browser cache and hard-refresh the dashboard.

See [SPEC.md § 9](SPEC.md#9-lovelace-card-security-sentinel-card) for full card options.

## 🗺️ Roadmap

See [SPEC.md § 13](SPEC.md#13-roadmap) for the full roadmap across three phases.

## 📄 License

MIT — see [LICENSE](LICENSE).
