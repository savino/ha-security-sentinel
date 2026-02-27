# Copilot Instructions — ha-security-sentinel

## Project Overview

**Security Sentinel** is a custom Home Assistant (HA) integration that provides real-time security monitoring. It detects unauthorized access attempts, enriches events with IP geolocation, fires multi-channel alerts, and exposes sensor entities and a custom Lovelace dashboard card.

- **Current version:** 0.2.0 (in `manifest.json`)
- **HA minimum version:** 2024.1.0
- **License:** MIT
- **HACS-compatible:** yes (`hacs.json` at repo root)

---

## Repository Layout

```
ha-security-sentinel/
├── .github/
│   ├── copilot-instructions.md    # this file
│   └── workflows/
│       ├── ci.yml                 # lint + hassfest + HACS validation
│       └── release.yml            # tag-triggered GitHub release
├── custom_components/
│   └── security_sentinel/         # ALL Python source lives here
│       ├── __init__.py            # Entry point; sets up coordinator, monitor, store, service
│       ├── manifest.json          # Integration metadata and version
│       ├── config_flow.py         # Multi-step UI config & options flow
│       ├── coordinator.py         # DataUpdateCoordinator; aggregates metrics + dispatch
│       ├── const.py               # All constants and defaults (edit here first)
│       ├── sensor.py              # Four sensor entities
│       ├── event_monitor.py       # HA event bus subscriber + brute-force detection
│       ├── geo_lookup.py          # Async IP geolocation with TTL cache
│       ├── actions.py             # Notification and SMTP email dispatcher
│       ├── store.py               # Persistent JSON event storage via HA Store
│       ├── services.yaml          # unban_ip service schema
│       ├── strings.json           # UI labels for config flow
│       └── frontend/
│           └── security-sentinel-card.js  # Lovelace card (ES module, Lit 2.x)
├── hacs.json
├── README.md                      # User-facing docs and configuration guide
└── SPEC.md                        # Technical specification (architecture, data flows)
```

---

## Key Technologies

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11+, async/await throughout |
| HA integration framework | `homeassistant.config_entries`, `DataUpdateCoordinator`, `voluptuous` |
| HTTP (geo lookup) | `aiohttp` (HA built-in) |
| Config validation | `voluptuous` schemas |
| Persistent storage | `homeassistant.helpers.storage.Store` (JSON) |
| Frontend card | JavaScript ES module, Lit 2.x |
| External APIs | ip-api.com (free, 45 req/min), ipinfo.io (with optional key) |

---

## How to Lint / Validate

There is **no `requirements.txt`** or `setup.py`; all Python dependencies ship with Home Assistant.

### Python linting (ruff)

```bash
pip install ruff
ruff check custom_components/ --select E,W,F --ignore E501
```

E501 (line-length) is intentionally ignored project-wide.

### Home Assistant integration validation (hassfest)

Run via GitHub Actions (`ci.yml` → `validate` job) or locally with the official action:

```bash
# requires Docker
docker run --rm -v $(pwd):/github/workspace homeassistant/hassfest
```

### HACS validation

Handled by the `hacs` CI job using `hacs/action@main`. No local equivalent is needed.

---

## CI Pipeline (`.github/workflows/ci.yml`)

Triggered on push to `main`/`develop` and PR to `main`.

| Job | Tool | What it checks |
|-----|------|---------------|
| `validate` | hassfest | Integration structure, manifest fields, platform declarations |
| `lint` | ruff | Python code style (E, W, F rules; E501 ignored) |
| `hacs` | hacs/action | HACS integration category conformance |

**All three jobs must pass before merging.** If any CI job fails, check:
1. `manifest.json` — `domain`, `version`, `config_flow`, `iot_class`, `requirements` all required
2. Python files — run `ruff check custom_components/ --select E,W,F --ignore E501` locally
3. `hacs.json` — `name` and `render_readme` fields must be present

---

## Release Process (`.github/workflows/release.yml`)

Push a semver tag (e.g. `git tag v0.2.1 && git push origin v0.2.1`).
The workflow verifies that `manifest.json` `"version"` matches the tag, then creates a GitHub release with auto-generated notes.

**Important:** Always bump `manifest.json` `"version"` to match the new tag before tagging.

---

## Module Reference

### `const.py` — Change constants here first

All tunable defaults and string constants live here. When adding a new config option:
1. Add `CONF_*` key constant.
2. Add `DEFAULT_*` value if applicable.
3. Update `config_flow.py` schema and `strings.json`.

### `__init__.py` — Entry point

- `async_setup_entry`: wires up `EventStore` → `SecuritySentinelCoordinator` → `EventMonitor`; copies Lovelace card to `/config/www/`; registers `unban_ip` service.
- `async_unload_entry`: stops monitor, unloads platforms.
- `async_reload_entry`: called when options change (unload + setup).

### `coordinator.py` — Data aggregation

Subclasses `DataUpdateCoordinator`. `_async_update_data` is the central refresh:
- Reads persisted events from store
- Calculates aggregate threat level using `THREAT_THRESHOLDS` / `SEVERITY_SCORES`
- Triggers geo enrichment and action dispatch via `actions.py`

### `event_monitor.py` — Detection engine

Subscribes to HA's internal event bus. Implements:
- `AUTH_FAILED` — `homeassistant_login_attempt` events
- `BRUTE_FORCE` — sliding-window counter over `AUTH_FAILED` events (configurable threshold/window)
- `NEW_DEVICE` — `device_registry_updated` events
- `SUSPICIOUS_SERVICE` — `call_service` events matching `SUSPICIOUS_SERVICES` list in `const.py`

All detected events are appended to `EventStore` and trigger a coordinator refresh.

### `geo_lookup.py` — IP enrichment

- Primary API: `ip-api.com` (no key; 45 req/min)
- Fallback API: `ipinfo.io` (optional `CONF_GEO_API_KEY`)
- Private IPs (matching `PRIVATE_IP_PREFIXES` in `const.py`) are skipped immediately
- In-memory TTL cache: one dict keyed by IP

### `actions.py` — Notifications

Dispatches:
1. HA persistent notification (`persistent_notification.create`)
2. HA bus event (`security_sentinel_event`)
3. Optional: `notify.*` service call (configurable)
4. Optional: SMTP email (configurable host/port/credentials)

### `sensor.py` — Sensor entities

Four sensors (all under `sensor.security_sentinel_*`):

| Key | What it exposes |
|-----|----------------|
| `failed_logins` | count since last restart |
| `threat_level` | `low` / `medium` / `high` / `critical` |
| `last_event` | ISO timestamp of most recent event |
| `banned_ips` | count of entries in `ip_bans.yaml` |

### `store.py` — Persistence

Wraps `homeassistant.helpers.storage.Store`. Events survive HA restarts. Key:
`security_sentinel.events`, version 1.

### `config_flow.py` — UI configuration

Two steps:
1. **user** — scan interval, failed-login threshold, brute-force window, notify service
2. **email** — optional SMTP/email credentials + optional ipinfo.io API key

Also implements `OptionsFlow` so settings are editable without reinstalling.

### `frontend/security-sentinel-card.js` — Lovelace card

ES module using Lit 2.x. On integration setup, `__init__.py` copies this file to `/config/www/`. Users must register the resource URL in Lovelace:

```yaml
url: /local/security-sentinel-card.js
type: module
```

---

## Configuration Options (via HA UI)

| Option constant | Default | Description |
|-----------------|---------|-------------|
| `CONF_SCAN_INTERVAL` | 60 s | Coordinator refresh interval |
| `CONF_FAILED_LOGIN_THRESHOLD` | 5 | Auth failures before brute-force alert |
| `CONF_BRUTE_FORCE_WINDOW` | 60 s | Sliding window for brute-force detection |
| `CONF_NOTIFY_SERVICE` | `persistent_notification` | HA notify service name |
| `CONF_EMAIL_RECIPIENT` | — | Alert email address |
| `CONF_SMTP_HOST` | — | SMTP server hostname |
| `CONF_SMTP_PORT` | 587 | SMTP port |
| `CONF_SMTP_USERNAME` | — | SMTP credentials |
| `CONF_SMTP_PASSWORD` | — | SMTP credentials |
| `CONF_GEO_API_KEY` | — | ipinfo.io API token (optional) |

---

## Common Tasks & Patterns

### Adding a new event type

1. Add an `EVENT_*` constant in `const.py`.
2. Add the detection handler in `event_monitor.py` (subscribe to the relevant HA event, build the event dict, call `self._store.async_add_event(...)` and `self._coordinator.async_request_refresh()`).
3. Update `actions.py` if the new event needs a different notification format.
4. Update `SPEC.md` event-type table.

### Adding a new sensor

1. Add a `SENSOR_*` key constant in `const.py`.
2. Extend `coordinator.py` to compute the new value in `_async_update_data`.
3. Add a new `SecuritySentinelSensor` subclass or entry in `sensor.py`.

### Adding a new config option

1. Add `CONF_*` and `DEFAULT_*` in `const.py`.
2. Add the field to the relevant `vol.Schema` in `config_flow.py`.
3. Add the label in `strings.json`.
4. Consume the value in the appropriate module using `entry.data.get(CONF_*, DEFAULT_*)`.

### Updating the integration version

1. Edit `"version"` in `manifest.json`.
2. Tag the commit with the matching semver tag to trigger the release workflow.

---

## Known Issues / Workarounds

- **No test suite:** The repository has no `pytest` or `homeassistant.test` infrastructure. Validation relies entirely on CI (`hassfest` + `ruff` + HACS). When adding tests, use `pytest-homeassistant-custom-component` and place them under a `tests/` directory.
- **`yaml` import in `__init__.py`:** `pyyaml` is used to read/write `ip_bans.yaml`. It is included in the HA runtime environment, but is not listed in `manifest.json` `"requirements"` (intentional — it is a HA core dependency).
- **Lovelace card auto-copy:** The card is copied on every `async_setup_entry` call if the source file is newer than the destination. If the card is not updating in the browser, clear the HA frontend cache or force-reload the resource.
- **Geo API rate limits:** `ip-api.com` allows 45 requests/minute. Under heavy attack scenarios many identical IPs may be queued; the in-memory TTL cache (`geo_lookup.py`) mitigates repeated lookups for the same IP.
