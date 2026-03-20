/**
 * Security Sentinel Card — Custom Lovelace Card for Home Assistant
 * Version: 0.2.0
 * Displays security events with geo enrichment, threat badge, expandable rows,
 * banned IPs list with unban action, and enriched new-device events.
 */

const SEVERITY_COLORS = {
  low: '#4CAF50',
  medium: '#FF9800',
  high: '#f44336',
  critical: '#9C27B0',
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

class SecuritySentinelCard extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this._config = {};
    this._expanded = new Set();
    this._bannedExpanded = new Set();
    this._activeTab = 'events';
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
    this._render();
  }

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

  _toggle(idx) {
    this._expanded.has(idx) ? this._expanded.delete(idx) : this._expanded.add(idx);
    this._render();
  }

  _unbanIP(ip) {
    if (!this._hass) return;
    this._hass.callService('security_sentinel', 'unban_ip', { ip_address: ip });
  }

  _toggleBanned(ip) {
    this._bannedExpanded.has(ip) ? this._bannedExpanded.delete(ip) : this._bannedExpanded.add(ip);
    this._render();
  }

  _setTab(tab) {
    this._activeTab = tab;
    this._render();
  }

  _handleListClick(event) {
    const actionTarget = event.target.closest('[data-action]');
    if (!actionTarget) return;

    const { action, idx, ip } = actionTarget.dataset;
    if (action === 'toggle-event' && idx != null) {
      this._toggle(parseInt(idx, 10));
      return;
    }

    if (action === 'toggle-banned' && ip) {
      this._toggleBanned(ip);
      return;
    }

    if (action === 'unban' && ip) {
      event.stopPropagation();
      this._unbanIP(ip);
    }
  }

  _handleListKeydown(event) {
    if (event.key !== 'Enter' && event.key !== ' ') return;

    const actionTarget = event.target.closest('[data-action="toggle-event"], [data-action="toggle-banned"]');
    if (!actionTarget) return;
    // Only intercept when the focused element itself is the toggle target,
    // not when a child element (e.g. unban-btn) bubbles up to a parent toggle.
    if (actionTarget !== event.target) return;

    event.preventDefault();
    this._handleListClick(event);
  }

  _renderEventsTab(events) {
    if (events.length === 0) {
      return `<div class="no-events">No recent security events \uD83C\uDF89</div>`;
    }
    return events.map((e, idx) => {
      const expanded = this._expanded.has(idx);
      const color    = SEVERITY_COLORS[e.severity] ?? '#607D8B';
      const geo      = e.geo ?? {};
      const flag     = countryFlag(geo.country_code || geo.country || '');
      const ago      = timeAgo(e.timestamp);
      const fullTs   = e.timestamp ? new Date(e.timestamp).toLocaleString() : '';
      const devInfo  = e.device_info ?? {};

      let detailRows = `
        <div class="geo-grid">
          <span>\uD83C\uDF0D Country</span><span>${escapeHtml(geo.country || '?')} (${escapeHtml(geo.country_code || '?')})</span>
          <span>\uD83C\uDFD9\uFE0F City</span><span>${escapeHtml(geo.city || '?')}</span>
          <span>\uD83C\uDFE2 ISP / Org</span><span>${escapeHtml(geo.org || geo.isp || '?')}</span>
          <span>\uD83D\uDCCD Region</span><span>${escapeHtml(geo.region || '?')}</span>
          <span>\uD83D\uDD50 Timezone</span><span>${escapeHtml(geo.timezone || '?')}</span>
          ${geo.lat != null ? `<span>\uD83D\uDDFA\uFE0F Coords</span><span>${geo.lat}, ${geo.lon}</span>` : ''}
        </div>`;

      // For NEW_DEVICE events, show device registry details
      if (e.event_type === 'NEW_DEVICE' && Object.keys(devInfo).length > 0) {
        detailRows += `
        <div class="device-grid">
          <span>\uD83D\uDCF1 Device ID</span><span>${escapeHtml(devInfo.device_id || '?')}</span>
          ${devInfo.name        ? `<span>\uD83C\uDFF7\uFE0F Name</span><span>${escapeHtml(devInfo.name)}</span>` : ''}
          ${devInfo.manufacturer ? `<span>\uD83C\uDFED Manufacturer</span><span>${escapeHtml(devInfo.manufacturer)}</span>` : ''}
          ${devInfo.model       ? `<span>\uD83D\uDCE6 Model</span><span>${escapeHtml(devInfo.model)}</span>` : ''}
          ${devInfo.entry_type  ? `<span>\uD83D\uDD16 Type</span><span>${escapeHtml(devInfo.entry_type)}</span>` : ''}
        </div>`;
      }

      const detail = expanded ? `
        <div class="evt-detail">
          ${detailRows}
          <div class="evt-msg">${escapeHtml(e.detail || '')}</div>
          <div class="evt-ts">${fullTs}</div>
        </div>` : '';

      return `
        <div class="evt-row" data-idx="${idx}">
          <div class="evt-summary" data-action="toggle-event" data-idx="${idx}" role="button" tabindex="0" aria-expanded="${expanded}">
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
    if (bannedIPs.length === 0) {
      return `<div class="no-events">No IPs currently banned \uD83D\uDC4D</div>`;
    }
    return bannedIPs.map(entry => {
      const ip       = entry.ip || entry;
      const bannedAt = entry.banned_at ? new Date(entry.banned_at).toLocaleString() : '';
      const geo      = entry.geo || {};
      const flag     = countryFlag(geo.country_code || geo.country || '');
      const attempts = entry.attempt_count || 0;
      const events   = entry.events || [];
      const expanded = this._bannedExpanded.has(ip);

      const geoSection = `
        <div class="geo-grid">
          <span>\uD83C\uDF0D Country</span><span>${escapeHtml(geo.country || '?')} ${geo.country_code ? '(' + escapeHtml(geo.country_code) + ')' : ''}</span>
          <span>\uD83C\uDFD9\uFE0F City</span><span>${escapeHtml(geo.city || '?')}</span>
          <span>\uD83C\uDFE2 ISP / Org</span><span>${escapeHtml(geo.org || geo.isp || '?')}</span>
          ${geo.region ? `<span>\uD83D\uDCCD Region</span><span>${escapeHtml(geo.region)}</span>` : ''}
          ${geo.timezone ? `<span>\uD83D\uDD50 Timezone</span><span>${escapeHtml(geo.timezone)}</span>` : ''}
          ${geo.lat != null ? `<span>\uD83D\uDDFA\uFE0F Coords</span><span>${geo.lat}, ${geo.lon}</span>` : ''}
        </div>`;

      const historySection = events.length > 0 ? `
        <div class="ban-history">
          <div class="ban-history-title">\uD83D\uDCC5 Access attempt history (${events.length})</div>
          ${events.map(ev => `
            <div class="ban-evt">
              <span class="ban-evt-type">${escapeHtml(ev.event_type || '')}</span>
              <span class="ban-evt-ts">${ev.timestamp ? new Date(ev.timestamp).toLocaleString() : ''}</span>
              <span class="ban-evt-detail">${escapeHtml(ev.detail || '')}</span>
            </div>`).join('')}
        </div>` : '';

      const detail = expanded ? `
        <div class="ban-dossier">
          ${geoSection}
          ${historySection}
        </div>` : '';

      return `
        <div class="ban-row-wrap" data-ip="${escapeHtml(ip)}">
          <div class="ban-row" role="button" tabindex="0" data-action="toggle-banned" data-ip="${escapeHtml(ip)}" aria-expanded="${expanded}">
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
            <button class="unban-btn" type="button" data-action="unban" data-ip="${escapeHtml(ip)}">\uD83D\uDD13 Unban</button>
          </div>
          ${detail}
        </div>`;
    }).join('');
  }

  _render() {
    if (!this._hass) return;

    const failedSensor   = this._state('sensor.security_sentinel_failed_logins');
    const threatSensor   = this._state('sensor.security_sentinel_threat_level');
    const lastEvtSensor  = this._state('sensor.security_sentinel_last_event');
    const bannedSensor   = this._state('sensor.security_sentinel_banned_ips');

    const failedCount   = failedSensor?.state  ?? '0';
    const threatLevel   = threatSensor?.state  ?? 'low';
    const threatColor   = SEVERITY_COLORS[threatLevel] ?? '#607D8B';
    const totalEvents   = threatSensor?.attributes?.total_events_loaded ?? 0;
    const lastEvtType   = lastEvtSensor?.state ?? 'None';
    const bannedCount   = bannedSensor?.state  ?? '0';
    const events        = this._getEvents();
    const bannedIPs     = this._getBannedIPs();

    const isEvents = this._activeTab === 'events';
    const isBanned = this._activeTab === 'banned';

    const tabContent = isEvents
      ? this._renderEventsTab(events)
      : this._renderBannedTab(bannedIPs);

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
        .tabs   { display:flex; gap:4px; margin-bottom:8px; border-bottom:2px solid var(--divider-color,#e0e0e0); }
        .tab    { padding:6px 14px; cursor:pointer; font-size:.82em; font-weight:600; border-radius:4px 4px 0 0;
                  color:var(--secondary-text-color,#888); border:none; background:none; text-transform:uppercase; letter-spacing:.04em; }
        .tab.active { color:var(--primary-color,#03a9f4); border-bottom:2px solid var(--primary-color,#03a9f4); margin-bottom:-2px; }
        .tab-badge { display:inline-block; background:var(--error-color,#f44336); color:#fff; border-radius:8px;
                     padding:1px 6px; font-size:.72em; margin-left:4px; vertical-align:middle; }
        .list   { display:flex; flex-direction:column; gap:4px; }
        .evt-row{ border:1px solid var(--divider-color,#e0e0e0); border-radius:6px; overflow:hidden; }
        .evt-summary{ display:flex; align-items:center; gap:8px; padding:8px 10px; cursor:pointer;
                      background:var(--card-background-color,#fff); }
        .evt-summary:hover { background:var(--secondary-background-color,#f9f9f9); }
        .dot    { width:10px; height:10px; border-radius:50%; flex-shrink:0; }
        .evt-type{ font-weight:600; font-size:.85em; flex:1; }
        .evt-ip { font-size:.8em; color:var(--secondary-text-color,#666); font-family:monospace; }
        .evt-ago{ font-size:.74em; color:var(--secondary-text-color,#aaa); white-space:nowrap; }
        .arrow  { font-size:.7em; color:var(--secondary-text-color,#aaa); }
        .evt-detail{ padding:10px 14px; background:var(--secondary-background-color,#f5f5f5);
                     border-top:1px solid var(--divider-color,#e0e0e0); }
        .geo-grid, .device-grid {
          display:grid; grid-template-columns:140px 1fr; gap:4px 12px; font-size:.82em; margin-bottom:8px;
        }
        .device-grid { margin-top:6px; padding-top:6px; border-top:1px dashed var(--divider-color,#ddd); }
        .geo-grid span:nth-child(odd), .device-grid span:nth-child(odd){
          color:var(--secondary-text-color,#888); font-weight:500;
        }
        .evt-msg { font-size:.82em; margin-bottom:4px; word-break:break-all; }
        .evt-ts  { font-size:.74em; color:var(--secondary-text-color,#aaa); }
        .no-events{ text-align:center; padding:20px; color:var(--secondary-text-color,#888); font-size:.9em; }
        /* Banned IPs */
        .ban-row-wrap { border:1px solid var(--divider-color,#e0e0e0); border-radius:6px; overflow:hidden; }
        .ban-row { display:flex; align-items:center; justify-content:space-between; gap:8px;
                   padding:8px 12px; background:var(--card-background-color,#fff); cursor:pointer; }
        .ban-row:hover { background:var(--secondary-background-color,#f9f9f9); }
        .ban-info { display:flex; flex-direction:column; gap:2px; flex:1; }
        .ban-header { display:flex; align-items:center; gap:6px; flex-wrap:wrap; }
        .ban-flag { font-size:1.1em; }
        .ban-ip  { font-family:monospace; font-size:.88em; font-weight:600; }
        .ban-country { font-size:.8em; color:var(--secondary-text-color,#666); }
        .ban-attempts { font-size:.74em; background:var(--error-color,#f44336); color:#fff;
                        border-radius:8px; padding:1px 6px; }
        .ban-ts  { font-size:.74em; color:var(--secondary-text-color,#aaa); }
        .ban-geo-brief { font-size:.78em; color:var(--secondary-text-color,#777); }
        .ban-dossier { padding:10px 14px; background:var(--secondary-background-color,#f5f5f5);
                       border-top:1px solid var(--divider-color,#e0e0e0); }
        .ban-history { margin-top:8px; padding-top:8px; border-top:1px dashed var(--divider-color,#ddd); }
        .ban-history-title { font-size:.8em; font-weight:600; color:var(--secondary-text-color,#666);
                             margin-bottom:6px; }
        .ban-evt { display:grid; grid-template-columns:auto 1fr; gap:2px 8px; font-size:.78em;
                   padding:4px 0; border-bottom:1px solid var(--divider-color,#eee); }
        .ban-evt:last-child { border-bottom:none; }
        .ban-evt-type { font-weight:600; grid-row:1; }
        .ban-evt-ts { color:var(--secondary-text-color,#aaa); grid-row:1; text-align:right; }
        .ban-evt-detail { grid-column:1/-1; color:var(--secondary-text-color,#666); word-break:break-all; }
        .unban-btn { padding:4px 12px; border-radius:6px; border:none; cursor:pointer;
                     background:var(--error-color,#f44336); color:#fff; font-size:.78em; font-weight:bold;
                     white-space:nowrap; flex-shrink:0; }
        .unban-btn:hover { opacity:.85; }
      </style>
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
            Recent Events
            ${events.length > 0 ? `<span class="tab-badge">${events.length}</span>` : ''}
          </button>
          <button class="tab${isBanned ? ' active' : ''}" id="tab-banned">
            Banned IPs
            ${bannedIPs.length > 0 ? `<span class="tab-badge" style="background:#607D8B">${bannedIPs.length}</span>` : ''}
          </button>
        </div>
        <div class="list" id="list">${tabContent}</div>
      </ha-card>`;

    this.shadowRoot.querySelector('#tab-events')
      ?.addEventListener('click', () => this._setTab('events'));
    this.shadowRoot.querySelector('#tab-banned')
      ?.addEventListener('click', () => this._setTab('banned'));

    this.shadowRoot.querySelector('#list')
      ?.addEventListener('click', (event) => this._handleListClick(event));
    this.shadowRoot.querySelector('#list')
      ?.addEventListener('keydown', (event) => this._handleListKeydown(event));
  }

  getCardSize() { return 5; }
}

customElements.define('security-sentinel-card', SecuritySentinelCard);

window.customCards = window.customCards || [];
window.customCards.push({
  type: 'security-sentinel-card',
  name: 'Security Sentinel Card',
  description: 'Timeline card for the Security Sentinel integration — shows events, geo data, threat level, and banned IPs.',
  preview: false,
});
