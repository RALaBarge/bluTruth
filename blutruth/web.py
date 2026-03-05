"""
blutruth.web — HTTP API + multi-column live Web UI

Progressive enhancement:
- Zero-JS baseline: server-rendered HTML with auto-refresh
- Live Mode (default): SSE streaming with ~100 lines of inline JS
- Multi-column layout: HCI | D-Bus | Daemon side by side

Endpoints:
  GET /                 → multi-column live UI
  GET /query            → history query panel (filter form + results)
  GET /device/<addr>    → device detail timeline
  GET /v1/events        → JSON query (source/severity/device/session_id/limit)
  GET /v1/stream        → SSE event stream
  GET /v1/status        → runtime stats
  GET /v1/devices/<addr>→ JSON device timeline
  POST /v1/events       → ingest external events

FUTURE: /v1/control endpoint for stack management actions
FUTURE (Rust port): axum with the same routes and SSE
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Optional

from aiohttp import web

from blutruth.bus import EventBus
from blutruth.events import Event
from blutruth.runtime import Runtime


def _esc(s: object) -> str:
    """HTML-escape a value for safe inline rendering."""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


class WebServer:
    def __init__(self, runtime: Runtime):
        self.runtime = runtime
        self.app = web.Application()
        self._setup_routes()

    def _setup_routes(self):
        self.app.router.add_get("/", self._handle_ui)
        self.app.router.add_get("/query", self._handle_query_ui)
        self.app.router.add_get(r"/device/{addr}", self._handle_device_ui)
        self.app.router.add_get("/v1/events", self._handle_events)
        self.app.router.add_post("/v1/events", self._handle_ingest)
        self.app.router.add_get("/v1/stream", self._handle_stream)
        self.app.router.add_get("/v1/status", self._handle_status)
        self.app.router.add_get(r"/v1/devices/{addr}", self._handle_device_api)

    async def _handle_status(self, request: web.Request) -> web.Response:
        return web.json_response(self.runtime.stats)

    async def _handle_events(self, request: web.Request) -> web.Response:
        limit = min(int(request.query.get("limit", "200")), 2000)
        source = request.query.get("source") or None
        severity = request.query.get("severity") or None
        device = request.query.get("device") or None
        sid_raw = request.query.get("session_id")
        session_id = int(sid_raw) if sid_raw and sid_raw.isdigit() else None
        rows = await self.runtime.sqlite.query_filtered(
            limit=limit, source=source, severity=severity,
            device=device, session_id=session_id,
        )
        return web.json_response({"data": rows})

    async def _handle_ingest(self, request: web.Request) -> web.Response:
        """Ingest an externally-sourced event into the bus."""
        try:
            body = await request.json()
        except Exception:
            raise web.HTTPBadRequest(reason="Invalid JSON body")

        summary = body.get("summary", "").strip()
        if not summary:
            raise web.HTTPBadRequest(reason="'summary' field is required")

        raw_json = body.get("raw_json", {})
        if not isinstance(raw_json, dict):
            raise web.HTTPBadRequest(reason="'raw_json' must be an object")

        valid_sources = {"HCI", "DBUS", "DAEMON", "KERNEL", "SYSFS", "RUNTIME"}
        source = body.get("source", "RUNTIME").upper()
        if source not in valid_sources:
            source = "RUNTIME"

        valid_severities = {"DEBUG", "INFO", "WARN", "ERROR", "SUSPICIOUS"}
        severity = body.get("severity", "INFO").upper()
        if severity not in valid_severities:
            severity = "INFO"

        ev = Event.new(
            source=source,
            event_type=body.get("event_type", "EXTERNAL_INGEST"),
            summary=summary,
            raw_json=raw_json,
            severity=severity,
            device_addr=body.get("device_addr") or None,
            device_name=body.get("device_name") or None,
        )
        await self.runtime.bus.publish(ev)
        return web.json_response({"ts_wall": ev.ts_wall, "ts_mono_us": ev.ts_mono_us}, status=201)

    async def _handle_device_api(self, request: web.Request) -> web.Response:
        addr = request.match_info["addr"].upper()
        limit = min(int(request.query.get("limit", "1000")), 5000)
        info = await self.runtime.sqlite.query_device_info(addr)
        if not info:
            raise web.HTTPNotFound(reason=f"No events for device {addr}")
        events = await self.runtime.sqlite.query_device_timeline(addr, limit=limit)
        return web.json_response({"device": info, "events": events})

    async def _handle_stream(self, request: web.Request) -> web.StreamResponse:
        """Server-Sent Events stream."""
        resp = web.StreamResponse()
        resp.content_type = "text/event-stream"
        resp.headers["Cache-Control"] = "no-cache"
        resp.headers["X-Accel-Buffering"] = "no"
        await resp.prepare(request)

        queue = await self.runtime.bus.subscribe(max_queue=2000)
        try:
            await resp.write(b"event: hello\ndata: {}\n\n")
            while True:
                ev = await queue.get()
                payload = json.dumps(ev.to_dict(), ensure_ascii=False, default=str)
                await resp.write(f"event: ev\ndata: {payload}\n\n".encode())
        except (asyncio.CancelledError, ConnectionResetError):
            pass
        finally:
            await self.runtime.bus.unsubscribe(queue)
        return resp

    # --- Shared helpers ---

    @staticmethod
    def _base_css() -> str:
        return """
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: 'SF Mono', 'Menlo', 'Monaco', 'Consolas', monospace;
    background: #0a0a0f; color: #c8c8d0; font-size: 12px;
}
a { color: #6c9eff; text-decoration: none; }
a:hover { text-decoration: underline; }
.topbar {
    display: flex; align-items: center; gap: 16px;
    padding: 8px 16px; background: #12121a;
    border-bottom: 1px solid #1e1e2e; height: 40px; flex-shrink: 0;
}
.topbar h1 { font-size: 14px; font-weight: 700; color: #6c9eff; letter-spacing: 1px; }
.topbar .stats { color: #666; font-size: 11px; }
.topbar .dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; margin-right: 4px; }
.dot.live { background: #4ade80; animation: pulse 2s infinite; }
.dot.off  { background: #666; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
.nav-links { display: flex; gap: 12px; margin-left: 8px; }
.nav-links a { font-size: 11px; color: #888; }
.nav-links a:hover, .nav-links a.active { color: #6c9eff; }
.controls { margin-left: auto; display: flex; gap: 8px; align-items: center; }
.controls label { color: #888; font-size: 11px; cursor: pointer; }
.controls input[type="checkbox"] { margin-right: 3px; }
.controls button, button.btn {
    background: #1e1e2e; border: 1px solid #2a2a3a; color: #aaa;
    padding: 2px 10px; border-radius: 3px; cursor: pointer;
    font-family: inherit; font-size: 11px;
}
.controls button:hover, button.btn:hover { background: #2a2a3a; color: #fff; }
button.btn-primary { background: #1a2a4a; border-color: #2a4a7a; color: #6c9eff; }
button.btn-primary:hover { background: #1e3460; color: #9ab8ff; }
.sev-error   { color: #f87171; }
.sev-warn    { color: #fbbf24; }
.sev-info    { color: #c8c8d0; }
.sev-debug   { color: #555; }
.sev-suspicious { color: #c084fc; }
.stage-badge {
    display: inline-block; font-size: 9px; padding: 0 4px;
    border-radius: 2px; margin-left: 4px; font-weight: 600;
}
.stage-DISCOVERY  { background: #1e3a5f; color: #60a5fa; }
.stage-CONNECTION { background: #1e3a2e; color: #4ade80; }
.stage-HANDSHAKE  { background: #3a2e1e; color: #fbbf24; }
.stage-DATA       { background: #1e1e3a; color: #818cf8; }
.stage-AUDIO      { background: #2e1e3a; color: #c084fc; }
.stage-TEARDOWN   { background: #3a1e1e; color: #f87171; }
.src-HCI    { color: #22d3ee; }
.src-DBUS   { color: #818cf8; }
.src-DAEMON { color: #4ade80; }
.src-KERNEL { color: #fbbf24; }
.src-SYSFS  { color: #c084fc; }
.src-RUNTIME{ color: #888; }
"""

    async def _handle_query_ui(self, request: web.Request) -> web.Response:
        """History query panel — filter form + client-side fetched results."""
        sessions = await self.runtime.sqlite.get_sessions()
        session_opts = '<option value="">All sessions</option>' + "".join(
            f'<option value="{s["id"]}">[{s["id"]}] {s["name"] or ""}</option>'
            for s in sessions
        )
        css = self._base_css()
        html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>bluTruth · Query</title>
<style>
{css}
body {{ overflow-y: auto; }}
.page {{ padding: 24px; max-width: 1200px; margin: 0 auto; }}
.filter-bar {{
    display: flex; flex-wrap: wrap; gap: 8px; align-items: flex-end;
    background: #12121a; border: 1px solid #1e1e2e; border-radius: 4px;
    padding: 12px 16px; margin-bottom: 16px;
}}
.filter-bar label {{ display: flex; flex-direction: column; gap: 3px; font-size: 10px; color: #666; }}
.filter-bar select, .filter-bar input[type=text], .filter-bar input[type=number] {{
    background: #0d0d14; border: 1px solid #2a2a3a; color: #c8c8d0;
    padding: 4px 8px; border-radius: 3px; font-family: inherit; font-size: 11px;
    min-width: 120px;
}}
.filter-bar select:focus, .filter-bar input:focus {{ outline: 1px solid #6c9eff; }}
.results-header {{
    color: #555; font-size: 11px; margin-bottom: 8px; padding-bottom: 6px;
    border-bottom: 1px solid #1e1e2e;
}}
.ev-row {{
    display: flex; gap: 8px; padding: 5px 8px; border-bottom: 1px solid #111118;
    align-items: baseline; cursor: pointer; line-height: 1.5;
}}
.ev-row:hover {{ background: #14141e; }}
.ev-row .ts {{ color: #555; white-space: nowrap; flex-shrink: 0; }}
.ev-row .src {{ width: 60px; flex-shrink: 0; font-size: 11px; }}
.ev-row .sev {{ width: 50px; flex-shrink: 0; font-size: 10px; text-transform: uppercase; }}
.ev-row .summary {{ flex: 1; }}
.ev-row .device {{ color: #888; font-size: 11px; white-space: nowrap; }}
.ev-row .detail {{ display: none; color: #444; font-size: 10px; word-break: break-all; }}
.ev-row.expanded .detail {{ display: block; margin-top: 4px; }}
#results {{ margin-top: 4px; }}
</style></head><body>
<div class="topbar">
  <h1>bluTruth</h1>
  <nav class="nav-links">
    <a href="/">Live</a>
    <a href="/query" class="active">Query</a>
    <a href="/device/unknown" style="display:none">Device</a>
  </nav>
</div>
<div class="page">
<div class="filter-bar">
  <label>Source
    <select id="fSource">
      <option value="">All</option>
      <option>HCI</option><option>DBUS</option><option>DAEMON</option>
      <option>KERNEL</option><option>SYSFS</option><option>RUNTIME</option>
    </select>
  </label>
  <label>Severity
    <select id="fSeverity">
      <option value="">All</option>
      <option>DEBUG</option><option>INFO</option><option>WARN</option>
      <option>ERROR</option><option>SUSPICIOUS</option>
    </select>
  </label>
  <label>Session
    <select id="fSession">{session_opts}</select>
  </label>
  <label>Device address
    <input type="text" id="fDevice" placeholder="AA:BB:CC:DD:EE:FF" style="min-width:160px">
  </label>
  <label>Limit
    <input type="number" id="fLimit" value="500" min="1" max="2000" style="min-width:70px">
  </label>
  <button class="btn btn-primary" onclick="runQuery()" style="margin-top:16px">Run ▶</button>
</div>
<div class="results-header" id="resultsHeader">Enter filters and click Run.</div>
<div id="results"></div>
</div>
<script>
function esc(s) {{
    if (!s) return '';
    return s.toString().replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}}
async function runQuery() {{
    const p = new URLSearchParams();
    const src = document.getElementById('fSource').value;
    const sev = document.getElementById('fSeverity').value;
    const sid = document.getElementById('fSession').value;
    const dev = document.getElementById('fDevice').value.trim();
    const lim = document.getElementById('fLimit').value;
    if (src) p.set('source', src);
    if (sev) p.set('severity', sev);
    if (sid) p.set('session_id', sid);
    if (dev) p.set('device', dev);
    p.set('limit', lim || '500');
    const hdr = document.getElementById('resultsHeader');
    hdr.textContent = 'Loading…';
    try {{
        const r = await fetch('/v1/events?' + p.toString());
        const data = await r.json();
        renderResults(data.data || []);
    }} catch(e) {{
        hdr.textContent = 'Error: ' + e;
    }}
}}
function renderResults(rows) {{
    const hdr = document.getElementById('resultsHeader');
    const container = document.getElementById('results');
    hdr.textContent = rows.length + ' events' + (rows.length === 0 ? '' : ' (newest first)');
    container.innerHTML = '';
    for (const ev of rows) {{
        const sev = (ev.severity || 'INFO').toLowerCase();
        const src = ev.source || '';
        const ts = (ev.ts_wall || '').substring(11, 23);
        const stage = ev.stage ? `<span class="stage-badge stage-${{ev.stage}}">${{ev.stage}}</span>` : '';
        const devLink = ev.device_addr
            ? `<a class="device" href="/device/${{encodeURIComponent(ev.device_addr)}}">${{esc(ev.device_addr)}}${{ev.device_name ? ' (' + esc(ev.device_name) + ')' : ''}}</a>`
            : '';
        const div = document.createElement('div');
        div.className = 'ev-row';
        div.innerHTML =
            `<span class="ts">${{ts}}</span>` +
            `<span class="src src-${{src}}">${{src}}</span>` +
            `<span class="sev sev-${{sev}}">${{ev.severity}}</span>` +
            `<span class="summary sev-${{sev}}">${{stage}}${{esc(ev.summary)}}</span>` +
            devLink +
            `<div class="detail">${{esc(JSON.stringify(ev.raw_json))}}</div>`;
        div.addEventListener('click', () => div.classList.toggle('expanded'));
        container.appendChild(div);
    }}
}}
// Pre-fill from URL params (e.g. /query?device=AA:BB:CC)
(function() {{
    const p = new URLSearchParams(location.search);
    if (p.get('device')) document.getElementById('fDevice').value = p.get('device');
    if (p.get('source')) document.getElementById('fSource').value = p.get('source');
    if (p.get('severity')) document.getElementById('fSeverity').value = p.get('severity');
    if (p.get('session_id')) document.getElementById('fSession').value = p.get('session_id');
}})();
runQuery();
</script>
</body></html>"""
        return web.Response(text=html, content_type="text/html")

    async def _handle_device_ui(self, request: web.Request) -> web.Response:
        """Device detail page — full correlated timeline for one device."""
        addr = request.match_info["addr"].upper()
        info = await self.runtime.sqlite.query_device_info(addr)
        if not info:
            raise web.HTTPNotFound(reason=f"No events found for device {addr}")
        events = await self.runtime.sqlite.query_device_timeline(addr, limit=2000)

        # Group events by correlation group_id (None = uncorrelated)
        groups: dict = {}
        group_order: list = []
        for ev in events:
            gid = ev["group_id"]
            key = gid if gid is not None else "__none__"
            if key not in groups:
                groups[key] = []
                group_order.append(key)
            groups[key].append(ev)

        def _ev_html(ev: dict) -> str:
            sev = (ev.get("severity") or "INFO").lower()
            src = ev.get("source") or ""
            ts = (ev.get("ts_wall") or "")[:23]
            stage = ev.get("stage") or ""
            stage_html = f'<span class="stage-badge stage-{stage}">{stage}</span> ' if stage else ""
            raw = json.dumps(ev.get("raw_json") or {}, ensure_ascii=False)
            summary = ev.get("summary") or ""
            return (
                f'<div class="ev-row">'
                f'<span class="ts">{ts}</span>'
                f'<span class="src src-{src}">{src}</span>'
                f'<span class="sev sev-{sev}">{ev.get("severity","INFO")}</span>'
                f'<span class="summary sev-{sev}">{stage_html}{_esc(summary)}</span>'
                f'<div class="detail">{_esc(raw)}</div>'
                f'</div>'
            )

        groups_html = ""
        for key in group_order:
            evs = groups[key]
            if key == "__none__":
                header = f'<div class="group-header">Uncorrelated ({len(evs)} events)</div>'
            else:
                t0 = (evs[0].get("ts_wall") or "")[:19]
                header = f'<div class="group-header">Group #{key} &mdash; {t0} &mdash; {len(evs)} events</div>'
            groups_html += header + "".join(_ev_html(e) for e in evs)

        name_display = f" ({info['device_name']})" if info.get("device_name") else ""
        css = self._base_css()
        html = f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>bluTruth · {addr}</title>
<style>
{css}
body {{ overflow-y: auto; }}
.page {{ padding: 24px; max-width: 1200px; margin: 0 auto; }}
.device-header {{
    background: #12121a; border: 1px solid #1e1e2e; border-radius: 4px;
    padding: 16px; margin-bottom: 16px;
}}
.device-header h2 {{ font-size: 16px; color: #6c9eff; margin-bottom: 6px; }}
.device-meta {{ color: #666; font-size: 11px; display: flex; gap: 24px; flex-wrap: wrap; }}
.device-meta span {{ display: flex; gap: 6px; }}
.device-meta strong {{ color: #888; }}
.group-header {{
    background: #12121a; color: #555; font-size: 10px; font-weight: 700;
    letter-spacing: 0.5px; padding: 4px 8px; margin-top: 8px;
    border-left: 2px solid #2a2a3a; text-transform: uppercase;
}}
.ev-row {{
    display: flex; gap: 8px; padding: 5px 8px; border-bottom: 1px solid #111118;
    align-items: baseline; cursor: pointer; line-height: 1.5;
}}
.ev-row:hover {{ background: #14141e; }}
.ev-row .ts {{ color: #555; white-space: nowrap; flex-shrink: 0; }}
.ev-row .src {{ width: 60px; flex-shrink: 0; font-size: 11px; }}
.ev-row .sev {{ width: 50px; flex-shrink: 0; font-size: 10px; text-transform: uppercase; }}
.ev-row .summary {{ flex: 1; }}
.ev-row .detail {{ display: none; color: #444; font-size: 10px; word-break: break-all; }}
.ev-row.expanded .detail {{ display: block; margin-top: 4px; }}
</style>
<script>
document.addEventListener('click', e => {{
    const row = e.target.closest('.ev-row');
    if (row) row.classList.toggle('expanded');
}});
</script>
</head><body>
<div class="topbar">
  <h1>bluTruth</h1>
  <nav class="nav-links">
    <a href="/">Live</a>
    <a href="/query">Query</a>
  </nav>
</div>
<div class="page">
<div class="device-header">
  <h2>{addr}{name_display}</h2>
  <div class="device-meta">
    <span><strong>Events:</strong> {info['event_count']}</span>
    <span><strong>First seen:</strong> {(info['first_seen'] or '')[:19]}</span>
    <span><strong>Last seen:</strong> {(info['last_seen'] or '')[:19]}</span>
    <span><a href="/query?device={addr}">Filter in query panel →</a></span>
  </div>
</div>
{groups_html if groups_html else '<p style="color:#555;padding:20px">No events.</p>'}
</div>
</body></html>"""
        return web.Response(text=html, content_type="text/html")

    async def _handle_ui(self, request: web.Request) -> web.Response:
        stats = self.runtime.stats
        collectors_info = ", ".join(
            f"{name}({'✓' if info['running'] else '✗'})"
            for name, info in stats.get("collectors", {}).items()
        )
        ui_max_rows = int(self.runtime.config.get("ui", "max_rows", default=500))
        ui_refresh_s = int(self.runtime.config.get("ui", "fallback_refresh_seconds", default=5))
        ui_live_default = bool(self.runtime.config.get("ui", "live_mode_default", default=True))

        html = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>bluTruth</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}

body {{
    font-family: 'SF Mono', 'Menlo', 'Monaco', 'Consolas', monospace;
    background: #0a0a0f;
    color: #c8c8d0;
    font-size: 12px;
    overflow: hidden;
    height: 100vh;
}}

.topbar {{
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 8px 16px;
    background: #12121a;
    border-bottom: 1px solid #1e1e2e;
    height: 40px;
    flex-shrink: 0;
}}

.topbar h1 {{
    font-size: 14px;
    font-weight: 700;
    color: #6c9eff;
    letter-spacing: 1px;
}}

.topbar .stats {{
    color: #666;
    font-size: 11px;
}}

.topbar .dot {{
    width: 8px; height: 8px;
    border-radius: 50%;
    display: inline-block;
    margin-right: 4px;
}}

.dot.live {{ background: #4ade80; animation: pulse 2s infinite; }}
.dot.off  {{ background: #666; }}

@keyframes pulse {{
    0%, 100% {{ opacity: 1; }}
    50% {{ opacity: 0.4; }}
}}

.controls {{
    margin-left: auto;
    display: flex;
    gap: 8px;
    align-items: center;
}}

.controls label {{
    color: #888;
    font-size: 11px;
    cursor: pointer;
}}

.controls input[type="checkbox"] {{
    margin-right: 3px;
}}

.controls button {{
    background: #1e1e2e;
    border: 1px solid #2a2a3a;
    color: #aaa;
    padding: 2px 10px;
    border-radius: 3px;
    cursor: pointer;
    font-family: inherit;
    font-size: 11px;
}}

.controls button:hover {{ background: #2a2a3a; color: #fff; }}

.columns {{
    display: flex;
    height: calc(100vh - 40px);
}}

.column {{
    flex: 1;
    display: flex;
    flex-direction: column;
    border-right: 1px solid #1e1e2e;
    overflow: hidden;
}}

.column:last-child {{ border-right: none; }}

.col-header {{
    padding: 6px 12px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    border-bottom: 2px solid;
    flex-shrink: 0;
    display: flex;
    justify-content: space-between;
    align-items: center;
}}

.col-header .count {{
    font-weight: 400;
    opacity: 0.5;
}}

.col-hci .col-header      {{ color: #22d3ee; border-color: #22d3ee; background: rgba(34,211,238,0.05); }}
.col-dbus .col-header    {{ color: #818cf8; border-color: #818cf8; background: rgba(129,140,248,0.05); }}
.col-daemon .col-header  {{ color: #4ade80; border-color: #4ade80; background: rgba(74,222,128,0.05); }}
.col-kernel .col-header  {{ color: #fbbf24; border-color: #fbbf24; background: rgba(251,191,36,0.05); }}
.col-audio .col-header   {{ color: #c084fc; border-color: #c084fc; background: rgba(192,132,252,0.05); }}

.events {{
    flex: 1;
    overflow-y: auto;
    padding: 4px 0;
}}

/* Scrollbar */
.events::-webkit-scrollbar {{ width: 4px; }}
.events::-webkit-scrollbar-track {{ background: transparent; }}
.events::-webkit-scrollbar-thumb {{ background: #333; border-radius: 2px; }}

.ev {{
    padding: 3px 12px;
    border-bottom: 1px solid #111118;
    line-height: 1.5;
    animation: fadeIn 0.15s ease-out;
}}

@keyframes fadeIn {{
    from {{ opacity: 0; transform: translateY(-4px); }}
    to {{ opacity: 1; transform: translateY(0); }}
}}

.ev:hover {{ background: #14141e; }}

.ev .ts {{
    color: #555;
    margin-right: 6px;
}}

.ev .device, .ev a.device {{
    color: #888;
    font-size: 11px;
    text-decoration: none;
}}
.ev a.device:hover {{ color: #6c9eff; text-decoration: underline; }}

.ev .summary {{
    display: block;
    margin-top: 1px;
}}

.ev.sev-error .summary   {{ color: #f87171; }}
.ev.sev-warn .summary    {{ color: #fbbf24; }}
.ev.sev-info .summary    {{ color: #c8c8d0; }}
.ev.sev-debug .summary   {{ color: #555; }}
.ev.sev-suspicious .summary {{ color: #c084fc; }}

.ev .detail {{
    color: #444;
    font-size: 10px;
    margin-top: 2px;
    max-height: 0;
    overflow: hidden;
    transition: max-height 0.2s;
    word-break: break-all;
}}

.ev.expanded .detail {{
    max-height: 300px;
}}

.ev .stage {{
    display: inline-block;
    font-size: 9px;
    padding: 0 4px;
    border-radius: 2px;
    margin-left: 4px;
    font-weight: 600;
}}

.stage-DISCOVERY    {{ background: #1e3a5f; color: #60a5fa; }}
.stage-CONNECTION   {{ background: #1e3a2e; color: #4ade80; }}
.stage-HANDSHAKE    {{ background: #3a2e1e; color: #fbbf24; }}
.stage-DATA         {{ background: #1e1e3a; color: #818cf8; }}
.stage-AUDIO        {{ background: #2e1e3a; color: #c084fc; }}
.stage-TEARDOWN     {{ background: #3a1e1e; color: #f87171; }}

.empty-state {{
    color: #333;
    text-align: center;
    padding: 40px 20px;
    font-size: 11px;
}}

noscript .fallback-notice {{
    background: #1a1a2e;
    color: #888;
    padding: 10px 16px;
    font-size: 11px;
    text-align: center;
}}
</style>
</head>
<body>

<div class="topbar">
    <h1>bluTruth</h1>
    <nav class="nav-links">
        <a href="/" class="active" style="color:#6c9eff">Live</a>
        <a href="/query" style="color:#888">Query</a>
    </nav>
    <span class="stats">
        <span class="dot live" id="liveDot"></span>
        <span id="statusText">Collectors: {collectors_info}</span>
    </span>
    <div class="controls">
        <label><input type="checkbox" id="autoScroll" checked> Auto-scroll</label>
        <label><input type="checkbox" id="showDebug"> Debug</label>
        <label><input type="checkbox" id="verbose"> Verbose</label>
        <button onclick="clearAll()">Clear</button>
        <button onclick="location.reload()">Refresh</button>
    </div>
</div>

<noscript>
<div class="fallback-notice">
    JavaScript disabled. <a href="/v1/events?limit=100" style="color:#6c9eff">View events as JSON</a>
    <meta http-equiv="refresh" content="{ui_refresh_s}">
</div>
</noscript>

<div class="columns">
    <div class="column col-hci">
        <div class="col-header">
            <span>HCI</span>
            <span class="count" id="countHCI">0</span>
        </div>
        <div class="events" id="evHCI">
            <div class="empty-state">Waiting for HCI events...<br>Run with sudo for btmon access</div>
        </div>
    </div>
    <div class="column col-dbus">
        <div class="col-header">
            <span>D-Bus</span>
            <span class="count" id="countDBUS">0</span>
        </div>
        <div class="events" id="evDBUS">
            <div class="empty-state">Waiting for D-Bus signals...</div>
        </div>
    </div>
    <div class="column col-daemon">
        <div class="col-header">
            <span>Daemon</span>
            <span class="count" id="countDAEMON">0</span>
        </div>
        <div class="events" id="evDAEMON">
            <div class="empty-state">Waiting for daemon logs...</div>
        </div>
    </div>
    <div class="column col-kernel">
        <div class="col-header">
            <span>Kernel</span>
            <span class="count" id="countKERNEL">0</span>
        </div>
        <div class="events" id="evKERNEL">
            <div class="empty-state">Waiting for kernel events...<br>Run with sudo for mgmt + dmesg</div>
        </div>
    </div>
    <div class="column col-audio">
        <div class="col-header">
            <span>Audio</span>
            <span class="count" id="countAUDIO">0</span>
        </div>
        <div class="events" id="evAUDIO">
            <div class="empty-state">Waiting for PipeWire events...<br>Requires pw-dump or pactl</div>
        </div>
    </div>
</div>

<script>
(function() {{
    const MAX_EVENTS = {ui_max_rows};
    const LIVE_MODE_DEFAULT = {'true' if ui_live_default else 'false'};
    const counts = {{ HCI: 0, DBUS: 0, DAEMON: 0, KERNEL: 0, AUDIO: 0 }};
    const columns = {{
        HCI:    document.getElementById('evHCI'),
        DBUS:   document.getElementById('evDBUS'),
        DAEMON: document.getElementById('evDAEMON'),
        KERNEL: document.getElementById('evKERNEL'),
        AUDIO:  document.getElementById('evAUDIO'),
    }};
    const countEls = {{
        HCI:    document.getElementById('countHCI'),
        DBUS:   document.getElementById('countDBUS'),
        DAEMON: document.getElementById('countDAEMON'),
        KERNEL: document.getElementById('countKERNEL'),
        AUDIO:  document.getElementById('countAUDIO'),
    }};

    const autoScroll = document.getElementById('autoScroll');
    const showDebug = document.getElementById('showDebug');
    const verbose = document.getElementById('verbose');
    const liveDot = document.getElementById('liveDot');

    // Route sources to columns. RUNTIME goes to DAEMON, SYSFS to KERNEL.
    function getColumn(source) {{
        if (source === 'HCI')                    return 'HCI';
        if (source === 'DBUS')                   return 'DBUS';
        if (source === 'KERNEL' || source === 'SYSFS') return 'KERNEL';
        if (source === 'PIPEWIRE')               return 'AUDIO';
        return 'DAEMON';  // DAEMON, RUNTIME, and anything unknown
    }}

    function esc(s) {{
        if (!s) return '';
        return s.toString().replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }}

    function renderEvent(ev) {{
        const col = getColumn(ev.source);
        const container = columns[col];
        if (!container) return;

        // Clear empty state on first event
        const empty = container.querySelector('.empty-state');
        if (empty) empty.remove();

        // Filter debug
        if (ev.severity === 'DEBUG' && !showDebug.checked) return;

        const sev = (ev.severity || 'INFO').toLowerCase();
        const ts = ev.ts_wall ? ev.ts_wall.substring(11, 23) : '';
        const device = ev.device_addr || '';
        const deviceName = ev.device_name ? ` (${{esc(ev.device_name)}})` : '';
        const deviceHtml = device
            ? `<a class="device" href="/device/${{encodeURIComponent(device)}}" onclick="event.stopPropagation()">${{esc(device)}}${{deviceName}}</a>`
            : '';
        const stage = ev.stage ? `<span class="stage stage-${{ev.stage}}">${{ev.stage}}</span>` : '';

        const detail = verbose.checked
            ? `<div class="detail" style="max-height:300px">${{esc(JSON.stringify(ev.raw_json))}}</div>`
            : `<div class="detail">${{esc(JSON.stringify(ev.raw_json))}}</div>`;

        const div = document.createElement('div');
        div.className = `ev sev-${{sev}}`;
        div.innerHTML = `<span class="ts">${{ts}}</span>`
            + deviceHtml
            + stage
            + `<span class="summary">${{esc(ev.summary)}}</span>`
            + detail;

        div.addEventListener('click', () => div.classList.toggle('expanded'));

        container.appendChild(div);

        // Update count
        counts[col] = (counts[col] || 0) + 1;
        if (countEls[col]) countEls[col].textContent = counts[col];

        // Cap events
        while (container.children.length > MAX_EVENTS) {{
            container.removeChild(container.firstChild);
        }}

        // Auto-scroll
        if (autoScroll.checked) {{
            container.scrollTop = container.scrollHeight;
        }}
    }}

    window.clearAll = function() {{
        Object.values(columns).forEach(c => {{
            c.innerHTML = '';
        }});
        Object.keys(counts).forEach(k => counts[k] = 0);
        Object.values(countEls).forEach(el => el.textContent = '0');
    }};

    // SSE connection
    let es = null;
    let reconnectDelay = 1000;

    function connect() {{
        es = new EventSource('/v1/stream');

        es.addEventListener('hello', () => {{
            liveDot.className = 'dot live';
            reconnectDelay = 1000;
        }});

        es.addEventListener('ev', (e) => {{
            try {{
                renderEvent(JSON.parse(e.data));
            }} catch(err) {{
                console.error('Parse error:', err);
            }}
        }});

        es.onerror = () => {{
            liveDot.className = 'dot off';
            es.close();
            setTimeout(connect, reconnectDelay);
            reconnectDelay = Math.min(reconnectDelay * 2, 10000);
        }};
    }}

    if (LIVE_MODE_DEFAULT) {{
        connect();
    }} else {{
        liveDot.className = 'dot off';
    }}
}})();
</script>
</body>
</html>"""

        return web.Response(text=html, content_type="text/html")


async def start_web(runtime: Runtime, host: str = "127.0.0.1", port: int = 8484):
    """Start the web server alongside the runtime."""
    local_only = runtime.config.get("security", "local_only", default=True)
    if local_only and host not in ("127.0.0.1", "::1", "localhost"):
        print(
            f"WARNING: security.local_only is True but --host={host!r}. "
            "Set security.local_only: false in config to bind externally.",
            file=__import__("sys").stderr,
        )

    server = WebServer(runtime)
    runner = web.AppRunner(server.app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    return runner
