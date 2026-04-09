/**
 * Security Sentinel Card — Custom Lovelace Card for Home Assistant
 * Version: 0.2.1
 * Tabs: Recent Events | Banned IPs | Map
 *
 * Changes:
 *  - Fix: banned-IP rows now expand reliably on all PC browsers (direct listeners
 *         instead of event delegation; pointer-events:none on non-interactive children).
 *  - New: Map tab — Leaflet.js map with attack-IP markers, traceroute polylines,
 *         and count/time filters (last 10/25/50 IPs, today, last week, last month).
 */

const SEVERITY_COLORS = {
  low: '#4CAF50',
  medium: '#FF9800',
  high: '#f44336',
  critical: '#9C27B0',
};

// Numeric rank for severity comparison (higher = worse)
const SEVERITY_ORDER = { low: 0, medium: 1, high: 2, critical: 3 };

// Time-window durations (ms) used by the map filter
const MAP_TIME_WINDOWS = {
  today: 86400e3,       // 24 h
  week:  7 * 86400e3,   // 7 days
  month: 30 * 86400e3,  // 30 days
};

function countryFlag(code) {
  if (!code || code.length < 2) return '\uD83C\uDF0D';
  const c = code.toUpperCase().slice(0, 2);
  return String.fromCodePoint(
    ...c.split('').map(ch => 0x1F1E6 + ch.charCodeAt(0) - 65)
  );
}

function timeAgo(isoString) {
  if (!isoString) return '';
  const diff = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ---------------------------------------------------------------------------
// Leaflet loader (global singleton — loaded once per page session)
// ---------------------------------------------------------------------------
let _leafletPromise = null;

function loadLeaflet() {
  if (_leafletPromise) return _leafletPromise;
  _leafletPromise = new Promise((resolve, reject) => {
    if (window.L) { resolve(window.L); return; }
    const script = document.createElement('script');
    script.src = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js';
    script.onload = () => resolve(window.L);
    script.onerror = () => { _leafletPromise = null; reject(new Error('Leaflet load failed')); };
    document.head.appendChild(script);
  });
  return _leafletPromise;
}

// ---------------------------------------------------------------------------
// Card class
// ---------------------------------------------------------------------------
class SecuritySentinelCard extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this._config = {};
    this._expanded = new Set();
    this._bannedExpanded = new Set();
    this._activeTab = 'events';
    this._map = null;
    this._mapLayers = [];
    this._mapFilter = { type: 'count', value: 10 };
    this._dossiers = {};
    this._mapData = null;
    this._isLoadingMap = false;
  }

  static getStubConfig() {
    return { title: 'Security Sentinel', max_events: 10, severity_filter: [] };
  }

  setConfig(config) {
    if (!config) throw new Error('Invalid configuration');
    this._config = {
      title: config.title || 'Security Sentinel',
      max_events: Number(config.max_events) || 10,
      severity_filter: Array.isArray(config.severity_filter) ? config.severity_filter : [],
    };
  }

  set hass(hass) {
    this._hass = hass;
    // When the map is already initialised, only refresh markers — avoid destroying the map
    if (this._activeTab === 'map' && this._map) {
      this._updateMapMarkers();
      return;
    }
    this._render();
  }

  // -------------------------------------------------------------------------
  // Data helpers
  // -------------------------------------------------------------------------
  _state(id) { return this._hass?.states?.[id] || null; }

  _getEvents() {
    const s = this._state('sensor.security_sentinel_failed_logins');
    let events = s?.attributes?.recent_events || [];
    const { severity_filter, max_events } = this._config;
    if (severity_filter.length) events = events.filter(e => severity_filter.includes(e.severity));
    return events.slice(0, max_events);
  }

  _getBannedIPs() {
    const s = this._state('sensor.security_sentinel_banned_ips');
    return s?.attributes?.banned_ips || [];
  }

  async _fetchBannedDossier(ip) {
    if (!this._hass) return null;
    try {
      return await this._hass.callWS({ type: 'security_sentinel/get_banned_dossier', ip: ip });
    } catch (e) {
      console.error(e);
      return null;
    }
  }

  async _fetchMapData() {
    if (!this._hass) return null;
    try {
      return await this._hass.callWS({ type: 'security_sentinel/get_map_data' });
    } catch (e) {
      console.error(e);
      return null;
    }
  }

  // 30-day event history exposed by the backend for the map tab
  _getAllMapEvents() {
    return this._mapData?.map_events || [];
  }

  // -------------------------------------------------------------------------
  // State mutations
  // -------------------------------------------------------------------------
  _toggle(idx) {
    this._expanded.has(idx) ? this._expanded.delete(idx) : this._expanded.add(idx);
    this._render();
  }

  async _toggleBanned(ip) {
    if (this._bannedExpanded.has(ip)) {
      this._bannedExpanded.delete(ip);
      this._render();
    } else {
      this._bannedExpanded.add(ip);
      this._render();
      if (!this._dossiers[ip]) {
        this._dossiers[ip] = await this._fetchBannedDossier(ip);
        this._render();
      }
    }
  }

  _unbanIP(ip) {
    if (!this._hass) return;
    this._hass.callService('security_sentinel', 'unban_ip', { ip_address: ip });
  }

  async _setTab(tab) {
    if (tab !== 'map' && this._map) {
      this._map.remove();
      this._map = null;
      this._mapLayers = [];
    }
    this._activeTab = tab;
    this._render();
    if (tab === 'map') {
      if (!this._mapData && !this._isLoadingMap) {
        this._isLoadingMap = true;
        this._mapData = await this._fetchMapData();
        this._isLoadingMap = false;
        if (this._activeTab === 'map') {
          this._updateMapFiltersUI();
          this._updateMapMarkers();
        }
      }
    }
  }

  _setMapFilter(type, value) {
    this._mapFilter = { type, value };
    if (this._activeTab === 'map') {
      if (this._map) { this._updateMapFiltersUI(); this._updateMapMarkers(); }
      else { this._render(); }
    }
  }

  // -------------------------------------------------------------------------
  // HTML renderers
  // -------------------------------------------------------------------------
  _renderEventsTab(events) {
    if (!events.length) return '<div class="no-events">No recent security events \uD83C\uDF89</div>';
    return events.map((e, idx) => {
      const expanded = this._expanded.has(idx);
      const color = SEVERITY_COLORS[e.severity] ?? '#607D8B';
      const geo = e.geo ?? {};
      const flag = countryFlag(geo.country_code || geo.country || '');
      const ago = timeAgo(e.timestamp);
      const fullTs = e.timestamp ? new Date(e.timestamp).toLocaleString() : '';
      const devInfo = e.device_info ?? {};

      let detailRows = `
        <div class="geo-grid">
          <span>\uD83C\uDF0D Country</span><span>${escapeHtml(geo.country || '?')} (${escapeHtml(geo.country_code || '?')})</span>
          <span>\uD83C\uDFD9\uFE0F City</span><span>${escapeHtml(geo.city || '?')}</span>
          <span>\uD83C\uDFE2 ISP / Org</span><span>${escapeHtml(geo.org || geo.isp || '?')}</span>
          <span>\uD83D\uDCCD Region</span><span>${escapeHtml(geo.region || '?')}</span>
          <span>\uD83D\uDD50 Timezone</span><span>${escapeHtml(geo.timezone || '?')}</span>
          ${geo.lat != null ? `<span>\uD83D\uDDFA\uFE0F Coords</span><span>${geo.lat}, ${geo.lon}</span>` : ''}
        </div>`;
      if (e.event_type === 'NEW_DEVICE' && Object.keys(devInfo).length > 0) {
        detailRows += `
        <div class="device-grid">
          <span>\uD83D\uDCF1 Device ID</span><span>${escapeHtml(devInfo.device_id || '?')}</span>
          ${devInfo.name ? `<span>\uD83C\uDFF7\uFE0F Name</span><span>${escapeHtml(devInfo.name)}</span>` : ''}
          ${devInfo.manufacturer ? `<span>\uD83C\uDFED Manufacturer</span><span>${escapeHtml(devInfo.manufacturer)}</span>` : ''}
          ${devInfo.model ? `<span>\uD83D\uDCE6 Model</span><span>${escapeHtml(devInfo.model)}</span>` : ''}
          ${devInfo.entry_type ? `<span>\uD83D\uDD16 Type</span><span>${escapeHtml(devInfo.entry_type)}</span>` : ''}
        </div>`;
      }
      const detail = expanded ? `
        <div class="evt-detail">
          ${detailRows}
          <div class="evt-msg">${escapeHtml(e.detail || '')}</div>
          <div class="evt-ts">${fullTs}</div>
        </div>` : '';
      return `
        <div class="evt-row">
          <div class="evt-summary" data-action="toggle-event" data-idx="${idx}"
               role="button" tabindex="0" aria-expanded="${expanded}">
            <span class="dot" style="background:${color}"></span>
            <span class="evt-type">${escapeHtml(e.event_type || 'Unknown')}</span>
            <span class="evt-ip">${escapeHtml(e.ip || 'N/A')} ${flag}</span>
            <span class="evt-ago">${ago}</span>
            <span class="arrow">${expanded ? '\u25B2' : '\u25BC'}</span>
          </div>
          ${detail}
        </div>`;
    }).join('');
  }

  _renderBannedTab(bannedIPs) {
    if (!bannedIPs.length) return '<div class="no-events">No IPs currently banned \uD83D\uDC4D</div>';
    return bannedIPs.map(entry => {
      const ip = entry.ip || entry;
      const bannedAt = entry.banned_at ? new Date(entry.banned_at).toLocaleString() : '';
      const geo = entry.geo || {};
      const flag = countryFlag(geo.country_code || geo.country || '');
      const attempts = entry.attempt_count || 0;
      const expanded = this._bannedExpanded.has(ip);
      const dossier = this._dossiers[ip];
      const events = dossier?.events || [];
      const isLoading = expanded && !dossier;

      const geoSection = `
        <div class="geo-grid">
          <span>\uD83C\uDF0D Country</span><span>${escapeHtml(geo.country || '?')} ${geo.country_code ? '(' + escapeHtml(geo.country_code) + ')' : ''}</span>
          <span>\uD83C\uDFD9\uFE0F City</span><span>${escapeHtml(geo.city || '?')}</span>
          <span>\uD83C\uDFE2 ISP / Org</span><span>${escapeHtml(geo.org || geo.isp || '?')}</span>
          ${geo.region ? `<span>\uD83D\uDCCD Region</span><span>${escapeHtml(geo.region)}</span>` : ''}
          ${geo.timezone ? `<span>\uD83D\uDD50 Timezone</span><span>${escapeHtml(geo.timezone)}</span>` : ''}
          ${geo.lat != null ? `<span>\uD83D\uDDFA\uFE0F Coords</span><span>${geo.lat}, ${geo.lon}</span>` : ''}
        </div>`;
      const historySection = isLoading ? `<div class="ban-history"><div class="ban-history-title">⏳ Loading history...</div></div>` :
        (events.length ? `
        <div class="ban-history">
          <div class="ban-history-title">\uD83D\uDCC5 Access attempt history (${events.length})</div>
          ${events.map(ev => `
            <div class="ban-evt">
              <span class="ban-evt-type">${escapeHtml(ev.event_type || '')}</span>
              <span class="ban-evt-ts">${ev.timestamp ? new Date(ev.timestamp).toLocaleString() : ''}</span>
              <span class="ban-evt-detail">${escapeHtml(ev.detail || '')}</span>
            </div>`).join('')}
        </div>` : '');
      const detail = expanded ? `
        <div class="ban-dossier">
          ${geoSection}
          ${historySection}
        </div>` : '';

      return `
        <div class="ban-row-wrap">
          <div class="ban-row" role="button" tabindex="0"
               data-action="toggle-banned" data-ip="${escapeHtml(ip)}"
               aria-expanded="${expanded}">
            <div class="ban-info">
              <div class="ban-header">
                <span class="ban-flag">${flag}</span>
                <span class="ban-ip">${escapeHtml(ip)}</span>
                ${geo.country ? `<span class="ban-country">${escapeHtml(geo.country)}</span>` : ''}
                ${attempts > 0 ? `<span class="ban-attempts">${attempts} attempt${attempts !== 1 ? 's' : ''}</span>` : ''}
                <span class="arrow">${expanded ? '\u25B2' : '\u25BC'}</span>
              </div>
              ${bannedAt ? `<div class="ban-ts">\uD83D\uDD12 Banned: ${bannedAt}</div>` : ''}
              ${geo.city || geo.org || geo.isp ? `<div class="ban-geo-brief">${escapeHtml(geo.city || '')}${geo.city && (geo.org || geo.isp) ? ' \u2022 ' : ''}${escapeHtml(geo.org || geo.isp || '')}</div>` : ''}
            </div>
            <button class="unban-btn" type="button"
                    data-action="unban" data-ip="${escapeHtml(ip)}">\uD83D\uDD13 Unban</button>
          </div>
          ${detail}
        </div>`;
    }).join('');
  }

  _renderMapTab() {
    const { type, value } = this._mapFilter;
    const ia = (t, v) => type === t && String(value) === String(v) ? ' active' : '';
    return `
      <div class="map-filters">
        <div class="filter-group">
          <span class="filter-label">Last</span>
          <button class="filter-btn${ia('count', 10)}" data-filter-type="count" data-filter-value="10">10 IPs</button>
          <button class="filter-btn${ia('count', 25)}" data-filter-type="count" data-filter-value="25">25 IPs</button>
          <button class="filter-btn${ia('count', 50)}" data-filter-type="count" data-filter-value="50">50 IPs</button>
        </div>
        <div class="filter-group">
          <button class="filter-btn${ia('time', 'today')}" data-filter-type="time" data-filter-value="today">Today</button>
          <button class="filter-btn${ia('time', 'week')}"  data-filter-type="time" data-filter-value="week">Last Week</button>
          <button class="filter-btn${ia('time', 'month')}" data-filter-type="time" data-filter-value="month">Last Month</button>
        </div>
      </div>
      <div id="sentinel-map"></div>
      <div id="map-note" class="map-note"></div>`;
  }

  // -------------------------------------------------------------------------
  // Main render — rebuilds shadow DOM
  // -------------------------------------------------------------------------
  _render() {
    if (!this._hass) return;

    const failedSensor  = this._state('sensor.security_sentinel_failed_logins');
    const threatSensor  = this._state('sensor.security_sentinel_threat_level');
    const lastEvtSensor = this._state('sensor.security_sentinel_last_event');
    const bannedSensor  = this._state('sensor.security_sentinel_banned_ips');

    const failedCount = failedSensor?.state  ?? '0';
    const threatLevel = threatSensor?.state  ?? 'low';
    const threatColor = SEVERITY_COLORS[threatLevel] ?? '#607D8B';
    const totalEvents = threatSensor?.attributes?.total_events_loaded ?? 0;
    const lastEvtType = lastEvtSensor?.state ?? 'None';
    const bannedCount = bannedSensor?.state  ?? '0';
    const events    = this._getEvents();
    const bannedIPs = this._getBannedIPs();

    const isEvents = this._activeTab === 'events';
    const isBanned = this._activeTab === 'banned';
    const isMap    = this._activeTab === 'map';

    let tabContent = '';
    if (isEvents) tabContent = this._renderEventsTab(events);
    else if (isBanned) tabContent = this._renderBannedTab(bannedIPs);
    else if (isMap) tabContent = this._renderMapTab();

    this.shadowRoot.innerHTML = `
      <style>
        :host { display:block; }
        ha-card { padding:16px; }
        .header { display:flex; align-items:center; justify-content:space-between; margin-bottom:12px; }
        .title  { font-size:1.1em; font-weight:bold; }
        .badge  { padding:3px 10px; border-radius:12px; color:#fff; font-size:.8em; font-weight:bold; text-transform:uppercase; }
        .stats  { display:flex; gap:16px; background:var(--secondary-background-color,#f5f5f5); border-radius:8px; padding:10px 14px; margin-bottom:12px; flex-wrap:wrap; }
        .stat   { display:flex; flex-direction:column; align-items:center; }
        .stat-v { font-size:1.35em; font-weight:bold; }
        .stat-l { font-size:.72em; color:var(--secondary-text-color,#888); text-transform:uppercase; }
        .tabs   { display:flex; gap:4px; margin-bottom:8px; border-bottom:2px solid var(--divider-color,#e0e0e0); flex-wrap:wrap; }
        .tab    { padding:6px 14px; cursor:pointer; font-size:.82em; font-weight:600; border-radius:4px 4px 0 0;
                  color:var(--secondary-text-color,#888); border:none; background:none; text-transform:uppercase; letter-spacing:.04em; }
        .tab.active { color:var(--primary-color,#03a9f4); border-bottom:2px solid var(--primary-color,#03a9f4); margin-bottom:-2px; }
        .tab-badge { display:inline-block; background:var(--error-color,#f44336); color:#fff; border-radius:8px;
                     padding:1px 6px; font-size:.72em; margin-left:4px; vertical-align:middle; }
        .list   { display:flex; flex-direction:column; gap:4px; }
        .evt-row { border:1px solid var(--divider-color,#e0e0e0); border-radius:6px; overflow:hidden; }
        .evt-summary { display:flex; align-items:center; gap:8px; padding:8px 10px; cursor:pointer;
                       background:var(--card-background-color,#fff); user-select:none; }
        .evt-summary:hover { background:var(--secondary-background-color,#f9f9f9); }
        .dot    { width:10px; height:10px; border-radius:50%; flex-shrink:0; }
        .evt-type { font-weight:600; font-size:.85em; flex:1; }
        .evt-ip   { font-size:.8em; color:var(--secondary-text-color,#666); font-family:monospace; }
        .evt-ago  { font-size:.74em; color:var(--secondary-text-color,#aaa); white-space:nowrap; }
        .arrow  { font-size:.7em; color:var(--secondary-text-color,#aaa); }
        .evt-detail { padding:10px 14px; background:var(--secondary-background-color,#f5f5f5);
                      border-top:1px solid var(--divider-color,#e0e0e0); }
        .geo-grid, .device-grid {
          display:grid; grid-template-columns:140px 1fr; gap:4px 12px; font-size:.82em; margin-bottom:8px;
        }
        .device-grid { margin-top:6px; padding-top:6px; border-top:1px dashed var(--divider-color,#ddd); }
        .geo-grid span:nth-child(odd), .device-grid span:nth-child(odd) {
          color:var(--secondary-text-color,#888); font-weight:500;
        }
        .evt-msg { font-size:.82em; margin-bottom:4px; word-break:break-all; }
        .evt-ts  { font-size:.74em; color:var(--secondary-text-color,#aaa); }
        .no-events { text-align:center; padding:20px; color:var(--secondary-text-color,#888); font-size:.9em; }
        /* --- Banned IPs --- */
        .ban-row-wrap { border:1px solid var(--divider-color,#e0e0e0); border-radius:6px; overflow:hidden; }
        .ban-row { display:flex; align-items:center; justify-content:space-between; gap:8px;
                   padding:8px 12px; background:var(--card-background-color,#fff);
                   cursor:pointer; user-select:none; }
        .ban-row:hover { background:var(--secondary-background-color,#f9f9f9); }
        /* pointer-events:none on .ban-info ensures the row element itself is the hit-target */
        .ban-info { display:flex; flex-direction:column; gap:2px; flex:1; min-width:0; pointer-events:none; }
        .ban-header { display:flex; align-items:center; gap:6px; flex-wrap:wrap; }
        .ban-flag { font-size:1.1em; }
        .ban-ip   { font-family:monospace; font-size:.88em; font-weight:600; }
        .ban-country { font-size:.8em; color:var(--secondary-text-color,#666); }
        .ban-attempts { font-size:.74em; background:var(--error-color,#f44336); color:#fff;
                        border-radius:8px; padding:1px 6px; }
        .ban-ts  { font-size:.74em; color:var(--secondary-text-color,#aaa); }
        .ban-geo-brief { font-size:.78em; color:var(--secondary-text-color,#777); }
        .ban-dossier { padding:10px 14px; background:var(--secondary-background-color,#f5f5f5);
                       border-top:1px solid var(--divider-color,#e0e0e0); }
        .ban-history { margin-top:8px; padding-top:8px; border-top:1px dashed var(--divider-color,#ddd); }
        .ban-history-title { font-size:.8em; font-weight:600; color:var(--secondary-text-color,#666); margin-bottom:6px; }
        .ban-evt { display:grid; grid-template-columns:auto 1fr; gap:2px 8px; font-size:.78em;
                   padding:4px 0; border-bottom:1px solid var(--divider-color,#eee); }
        .ban-evt:last-child { border-bottom:none; }
        .ban-evt-type   { font-weight:600; grid-row:1; }
        .ban-evt-ts     { color:var(--secondary-text-color,#aaa); grid-row:1; text-align:right; }
        .ban-evt-detail { grid-column:1/-1; color:var(--secondary-text-color,#666); word-break:break-all; }
        .unban-btn { padding:4px 12px; border-radius:6px; border:none; cursor:pointer;
                     background:var(--error-color,#f44336); color:#fff; font-size:.78em; font-weight:bold;
                     white-space:nowrap; flex-shrink:0; pointer-events:auto; position:relative; z-index:1; }
        .unban-btn:hover { opacity:.85; }
        /* --- Map tab --- */
        .map-filters { display:flex; flex-wrap:wrap; gap:6px; margin-bottom:8px; align-items:center; }
        .filter-group { display:flex; gap:4px; align-items:center; }
        .filter-label { font-size:.78em; color:var(--secondary-text-color,#888); margin-right:2px; }
        .filter-btn { padding:3px 10px; border-radius:12px; border:1px solid var(--divider-color,#ccc);
                      background:var(--card-background-color,#fff); cursor:pointer;
                      font-size:.78em; font-weight:600; color:var(--secondary-text-color,#666); }
        .filter-btn:hover { background:var(--secondary-background-color,#f5f5f5); }
        .filter-btn.active { background:var(--primary-color,#03a9f4); color:#fff; border-color:var(--primary-color,#03a9f4); }
        #sentinel-map { height:420px; border-radius:8px; border:1px solid var(--divider-color,#e0e0e0);
                        background:var(--secondary-background-color,#f5f5f5); }
        .map-error   { padding:30px; text-align:center; color:var(--secondary-text-color,#888); font-size:.9em; line-height:1.6; }
        .map-loading { padding:30px; text-align:center; color:var(--secondary-text-color,#888); font-size:.9em; }
        .map-note { margin-top:8px; text-align:center; color:var(--secondary-text-color,#888); font-size:.8em; }
      </style>
      ${isMap ? '<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">' : ''}
      <ha-card>
        <div class="header">
          <div class="title">\uD83D\uDEE1\uFE0F ${escapeHtml(this._config.title)}</div>
          <span class="badge" style="background:${threatColor}">${escapeHtml(threatLevel)}</span>
        </div>
        <div class="stats">
          <div class="stat"><span class="stat-v">${escapeHtml(failedCount)}</span><span class="stat-l">Failed Logins (24h)</span></div>
          <div class="stat"><span class="stat-v">${totalEvents}</span><span class="stat-l">Total Events</span></div>
          <div class="stat"><span class="stat-v" style="font-size:.88em">${escapeHtml(lastEvtType)}</span><span class="stat-l">Last Event</span></div>
          <div class="stat"><span class="stat-v" style="color:${parseInt(bannedCount)>0?'#f44336':'inherit'}">${escapeHtml(bannedCount)}</span><span class="stat-l">Banned IPs</span></div>
        </div>
        <div class="tabs">
          <button class="tab${isEvents ? ' active' : ''}" id="tab-events">
            Recent Events${events.length > 0 ? `<span class="tab-badge">${events.length}</span>` : ''}
          </button>
          <button class="tab${isBanned ? ' active' : ''}" id="tab-banned">
            Banned IPs${bannedIPs.length > 0 ? `<span class="tab-badge" style="background:#607D8B">${bannedIPs.length}</span>` : ''}
          </button>
          <button class="tab${isMap ? ' active' : ''}" id="tab-map">
            \uD83D\uDDFA\uFE0F Map
          </button>
        </div>
        <div class="list" id="list">${tabContent}</div>
      </ha-card>`;

    this._attachListeners();

    if (isMap) {
      requestAnimationFrame(() => this._initMapTab());
    }
  }

  // -------------------------------------------------------------------------
  // Event listeners — attached directly to each interactive element
  // -------------------------------------------------------------------------
  _attachListeners() {
    this.shadowRoot.querySelector('#tab-events')
      ?.addEventListener('click', () => this._setTab('events'));
    this.shadowRoot.querySelector('#tab-banned')
      ?.addEventListener('click', () => this._setTab('banned'));
    this.shadowRoot.querySelector('#tab-map')
      ?.addEventListener('click', () => this._setTab('map'));

    // Event rows — expand/collapse
    this.shadowRoot.querySelectorAll('[data-action="toggle-event"]').forEach(el => {
      const idx = parseInt(el.dataset.idx, 10);
      el.addEventListener('click', () => { if (!isNaN(idx)) this._toggle(idx); });
      el.addEventListener('keydown', e => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); if (!isNaN(idx)) this._toggle(idx); }
      });
    });

    // Banned-IP rows — direct per-element listener (fixes PC browser expand bug)
    // .ban-info has pointer-events:none so its child text/spans don't steal the click;
    // the .ban-row div is always the event.target when clicking inside the info area.
    this.shadowRoot.querySelectorAll('.ban-row').forEach(row => {
      const ip = row.dataset.ip;
      row.addEventListener('click', e => {
        if (e.target.closest('.unban-btn')) return; // unban button handles its own click
        if (ip) this._toggleBanned(ip);
      });
      row.addEventListener('keydown', e => {
        if (e.target.closest('.unban-btn')) return;
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); if (ip) this._toggleBanned(ip); }
      });
    });

    // Unban buttons — stopPropagation so the row-toggle listener above doesn't also fire
    this.shadowRoot.querySelectorAll('[data-action="unban"]').forEach(btn => {
      const ip = btn.dataset.ip;
      btn.addEventListener('click', e => { e.stopPropagation(); if (ip) this._unbanIP(ip); });
    });

    // Map filter buttons
    this.shadowRoot.querySelectorAll('.filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const raw = btn.dataset.filterValue;
        const value = isNaN(Number(raw)) ? raw : Number(raw);
        this._setMapFilter(btn.dataset.filterType, value);
      });
    });
  }

  // -------------------------------------------------------------------------
  // Map
  // -------------------------------------------------------------------------
  async _initMapTab() {
    const container = this.shadowRoot?.querySelector('#sentinel-map');
    if (!container) return;

    container.innerHTML = '<div class="map-loading">\uD83D\uDDFA\uFE0F Loading map\u2026</div>';

    let L;
    try {
      L = await loadLeaflet();
    } catch (_) {
      container.innerHTML = `
        <div class="map-error">
          \u26A0\uFE0F Map unavailable \u2014 Leaflet.js could not be loaded.<br>
          <small>Ensure your HA instance can reach <b>unpkg.com</b>.</small>
        </div>`;
      return;
    }

    container.innerHTML = '';

    this._map = L.map(container, { zoomControl: true }).setView([20, 0], 2);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '\u00A9 <a href="https://www.openstreetmap.org/copyright" target="_blank">OpenStreetMap</a> contributors',
      maxZoom: 18,
    }).addTo(this._map);

    this._updateMapMarkers();
  }

  _updateMapFiltersUI() {
    const { type, value } = this._mapFilter;
    this.shadowRoot.querySelectorAll('.filter-btn').forEach(btn => {
      btn.classList.toggle(
        'active',
        btn.dataset.filterType === type && String(btn.dataset.filterValue) === String(value)
      );
    });
  }

  _getMapData() {
    const { type, value } = this._mapFilter;
    const allEvents = this._getAllMapEvents();

    // Apply filter
    let filtered;
    if (type === 'count') {
      const seen = new Set();
      filtered = [];
      for (const ev of allEvents) {
        if (ev.ip && ev.ip !== 'N/A' && ev.ip !== 'internal' && !seen.has(ev.ip)) {
          seen.add(ev.ip);
          filtered.push(ev);
          if (seen.size >= value) break;
        }
      }
    } else {
      const cutoff = Date.now() - (MAP_TIME_WINDOWS[value] ?? MAP_TIME_WINDOWS.today);
      filtered = allEvents.filter(ev => {
        const ts = ev.timestamp ? new Date(ev.timestamp).getTime() : 0;
        return ts >= cutoff;
      });
    }

    // Build per-IP marker data (highest severity wins)
    const ipMap = new Map();
    for (const ev of filtered) {
      const geo = ev.geo || {};
      if (geo.lat == null || geo.lon == null) continue;
      if (!ipMap.has(ev.ip)) {
        ipMap.set(ev.ip, { ip: ev.ip, lat: geo.lat, lon: geo.lon, geo, severity: ev.severity || 'low', events: [] });
      }
      const entry = ipMap.get(ev.ip);
      entry.events.push(ev);
      if ((SEVERITY_ORDER[ev.severity] ?? 0) > (SEVERITY_ORDER[entry.severity] ?? 0)) entry.severity = ev.severity;
    }

    // Traceroute paths from banned IPs (all bans, not filtered — paths are always relevant)
    const traces = this._mapData?.traces || [];

    return { markers: Array.from(ipMap.values()), traces };
  }

  _updateMapMarkers() {
    if (!this._map || !window.L) return;
    const L = window.L;
    const note = this.shadowRoot?.querySelector('#map-note');

    this._mapLayers.forEach(l => { try { this._map.removeLayer(l); } catch (_) { /* layer already removed */ } });
    this._mapLayers = [];

    const { markers, traces } = this._getMapData();

    if (note) {
      note.textContent = markers.length || traces.length
        ? ''
        : 'No geolocated attacker IPs available yet. Markers appear when events or banned IP entries include coordinates.';
    }

    // Traceroute polylines (rendered first, behind attack markers)
    for (const trace of traces) {
      const line = L.polyline(trace.path, {
        color: '#9C27B0', weight: 2, opacity: 0.65, dashArray: '5 5',
      }).addTo(this._map);
      line.bindPopup(`Traceroute path to <b>${escapeHtml(trace.ip)}</b>`);
      this._mapLayers.push(line);

      // Small waypoint dots for intermediate hops
      trace.hops.forEach((hop, i) => {
        if (i === trace.hops.length - 1) return; // destination is shown as attack marker
        const dot = L.circleMarker([hop.lat, hop.lon], {
          radius: 3, fillColor: '#9C27B0', color: '#fff', weight: 1, fillOpacity: 0.7,
        }).addTo(this._map);
        dot.bindPopup(`Hop ${i + 1}: ${escapeHtml(hop.ip || '')}`);
        this._mapLayers.push(dot);
      });
    }

    // Attack-IP circle markers
    for (const m of markers) {
      const color = SEVERITY_COLORS[m.severity] ?? '#607D8B';
      const flag  = countryFlag(m.geo.country_code || m.geo.country || '');
      const circle = L.circleMarker([m.lat, m.lon], {
        radius: 9, fillColor: color, color: '#fff', weight: 2, fillOpacity: 0.85,
      }).addTo(this._map);
      circle.bindPopup(
        `<b>${escapeHtml(m.ip)}</b> ${flag}<br>` +
        `${escapeHtml(m.geo.country || '')}${m.geo.city ? ' \u00B7 ' + escapeHtml(m.geo.city) : ''}<br>` +
        `<i>${m.events.length} attempt(s) &bull; severity: ${m.severity}</i>`
      );
      this._mapLayers.push(circle);
    }

    // Fit bounds
    if (this._mapLayers.length > 0) {
      try {
        const bounds = L.featureGroup(this._mapLayers).getBounds();
        if (bounds.isValid()) this._map.fitBounds(bounds.pad(0.15), { maxZoom: 6 });
      } catch (_) { /* fitBounds fails on empty layer groups */ }
    }
  }

  getCardSize() { return 6; }
}

customElements.define('security-sentinel-card', SecuritySentinelCard);

window.customCards = window.customCards || [];
window.customCards.push({
  type: 'security-sentinel-card',
  name: 'Security Sentinel Card',
  description: 'Timeline card for the Security Sentinel integration — shows events, geo data, threat level, banned IPs, and an attack-origin map with traceroute paths.',
  preview: false,
});
