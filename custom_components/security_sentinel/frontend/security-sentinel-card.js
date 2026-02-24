/**
 * Security Sentinel Card — Custom Lovelace Card for Home Assistant
 * Version: 0.1.0
 * Displays security events with geo enrichment, threat badge, and expandable rows.
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

class SecuritySentinelCard extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this._config = {};
    this._expanded = new Set();
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

  _toggle(idx) {
    this._expanded.has(idx) ? this._expanded.delete(idx) : this._expanded.add(idx);
    this._render();
  }

  _render() {
    if (!this._hass) return;

    const failedSensor   = this._state('sensor.security_sentinel_failed_logins');
    const threatSensor   = this._state('sensor.security_sentinel_threat_level');
    const lastEvtSensor  = this._state('sensor.security_sentinel_last_event');

    const failedCount   = failedSensor?.state  ?? '0';
    const threatLevel   = threatSensor?.state  ?? 'low';
    const threatColor   = SEVERITY_COLORS[threatLevel] ?? '#607D8B';
    const totalEvents   = threatSensor?.attributes?.total_events_loaded ?? 0;
    const lastEvtType   = lastEvtSensor?.state ?? 'None';
    const events        = this._getEvents();

    const eventsHTML = events.length === 0
      ? `<div class="no-events">No recent security events \uD83C\uDF89</div>`
      : events.map((e, idx) => {
          const expanded = this._expanded.has(idx);
          const color    = SEVERITY_COLORS[e.severity] ?? '#607D8B';
          const geo      = e.geo ?? {};
          const flag     = countryFlag(geo.country_code || geo.country || '');
          const ago      = timeAgo(e.timestamp);
          const fullTs   = e.timestamp ? new Date(e.timestamp).toLocaleString() : '';

          const detail = expanded ? `
            <div class="evt-detail">
              <div class="geo-grid">
                <span>\uD83C\uDF0D Country</span><span>${geo.country || '?'} (${geo.country_code || '?'})</span>
                <span>\uD83C\uDFD9\uFE0F City</span><span>${geo.city || '?'}</span>
                <span>\uD83C\uDFE2 ISP / Org</span><span>${geo.org || geo.isp || '?'}</span>
                <span>\uD83D\uDCCD Region</span><span>${geo.region || '?'}</span>
                <span>\uD83D\uDD50 Timezone</span><span>${geo.timezone || '?'}</span>
                ${geo.lat != null ? `<span>\uD83D\uDDFA\uFE0F Coords</span><span>${geo.lat}, ${geo.lon}</span>` : ''}
              </div>
              <div class="evt-msg">${e.detail || ''}</div>
              <div class="evt-ts">${fullTs}</div>
            </div>` : '';

          return `
            <div class="evt-row" data-idx="${idx}">
              <div class="evt-summary">
                <span class="dot" style="background:${color}"></span>
                <span class="evt-type">${e.event_type || 'Unknown'}</span>
                <span class="evt-ip">${e.ip || 'N/A'} ${flag}</span>
                <span class="evt-ago">${ago}</span>
                <span class="arrow">${expanded ? '\u25B2' : '\u25BC'}</span>
              </div>
              ${detail}
            </div>`;
        }).join('');

    this.shadowRoot.innerHTML = `
      <style>
        :host { display:block; }
        ha-card { padding:16px; }
        .header { display:flex; align-items:center; justify-content:space-between; margin-bottom:12px; }
        .title  { font-size:1.1em; font-weight:bold; }
        .badge  { padding:3px 10px; border-radius:12px; color:#fff; font-size:.8em; font-weight:bold; text-transform:uppercase; }
        .stats  { display:flex; gap:16px; background:var(--secondary-background-color,#f5f5f5); border-radius:8px; padding:10px 14px; margin-bottom:12px; }
        .stat   { display:flex; flex-direction:column; align-items:center; }
        .stat-v { font-size:1.35em; font-weight:bold; }
        .stat-l { font-size:.72em; color:var(--secondary-text-color,#888); text-transform:uppercase; }
        .sec-lbl{ font-size:.78em; font-weight:bold; text-transform:uppercase; color:var(--secondary-text-color,#888); letter-spacing:.05em; margin-bottom:6px; }
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
        .geo-grid{ display:grid; grid-template-columns:130px 1fr; gap:4px 12px; font-size:.82em; margin-bottom:8px; }
        .geo-grid span:nth-child(odd){ color:var(--secondary-text-color,#888); font-weight:500; }
        .evt-msg { font-size:.82em; margin-bottom:4px; }
        .evt-ts  { font-size:.74em; color:var(--secondary-text-color,#aaa); }
        .no-events{ text-align:center; padding:20px; color:var(--secondary-text-color,#888); font-size:.9em; }
      </style>
      <ha-card>
        <div class="header">
          <div class="title">\uD83D\uDEE1\uFE0F ${this._config.title}</div>
          <span class="badge" style="background:${threatColor}">${threatLevel}</span>
        </div>
        <div class="stats">
          <div class="stat"><span class="stat-v">${failedCount}</span><span class="stat-l">Failed Logins (24h)</span></div>
          <div class="stat"><span class="stat-v">${totalEvents}</span><span class="stat-l">Total Events</span></div>
          <div class="stat"><span class="stat-v" style="font-size:.88em">${lastEvtType}</span><span class="stat-l">Last Event</span></div>
        </div>
        <div class="sec-lbl">Recent Events</div>
        <div class="list" id="list">${eventsHTML}</div>
      </ha-card>`;

    this.shadowRoot.querySelectorAll('.evt-summary').forEach(el => {
      el.addEventListener('click', () => {
        this._toggle(parseInt(el.closest('.evt-row').dataset.idx, 10));
      });
    });
  }

  getCardSize() { return 4; }
}

customElements.define('security-sentinel-card', SecuritySentinelCard);

window.customCards = window.customCards || [];
window.customCards.push({
  type: 'security-sentinel-card',
  name: 'Security Sentinel Card',
  description: 'Timeline card for the Security Sentinel integration — shows events, geo data and threat level.',
  preview: false,
});
