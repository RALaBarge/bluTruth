"""
blutruth.web — HTTP API + multi-column live Web UI

Progressive enhancement:
- Zero-JS baseline: server-rendered HTML with auto-refresh
- Live Mode (default): SSE streaming with ~100 lines of inline JS
- Multi-column layout: HCI | D-Bus | Daemon side by side

Endpoints:
  GET /            → multi-column live UI
  GET /v1/events   → JSON query (recent events)
  GET /v1/stream   → SSE event stream
  GET /v1/status   → runtime stats
  POST /v1/events  → ingest external events

FUTURE: /v1/control endpoint for stack management actions
FUTURE: Device detail pages, correlation group expansion
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


class WebServer:
    def __init__(self, runtime: Runtime):
        self.runtime = runtime
        self.app = web.Application()
        self._setup_routes()

    def _setup_routes(self):
        self.app.router.add_get("/", self._handle_ui)
        self.app.router.add_get("/v1/events", self._handle_events)
        self.app.router.add_get("/v1/stream", self._handle_stream)
        self.app.router.add_get("/v1/status", self._handle_status)

    async def _handle_status(self, request: web.Request) -> web.Response:
        return web.json_response(self.runtime.stats)

    async def _handle_events(self, request: web.Request) -> web.Response:
        limit = min(int(request.query.get("limit", "200")), 2000)
        rows = await self.runtime.sqlite.query_recent(limit=limit)
        return web.json_response({"data": rows})

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

    async def _handle_ui(self, request: web.Request) -> web.Response:
        stats = self.runtime.stats
        collectors_info = ", ".join(
            f"{name}({'✓' if info['running'] else '✗'})"
            for name, info in stats.get("collectors", {}).items()
        )

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

.ev .device {{
    color: #888;
    font-size: 11px;
}}

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
    <meta http-equiv="refresh" content="5">
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
    const MAX_EVENTS = 500;
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
        const stage = ev.stage ? `<span class="stage stage-${{ev.stage}}">${{ev.stage}}</span>` : '';

        const detail = verbose.checked
            ? `<div class="detail" style="max-height:300px">${{esc(JSON.stringify(ev.raw_json))}}</div>`
            : `<div class="detail">${{esc(JSON.stringify(ev.raw_json))}}</div>`;

        const div = document.createElement('div');
        div.className = `ev sev-${{sev}}`;
        div.innerHTML = `<span class="ts">${{ts}}</span>`
            + (device ? `<span class="device">${{esc(device)}}</span>` : '')
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

    connect();
}})();
</script>
</body>
</html>"""

        return web.Response(text=html, content_type="text/html")


async def start_web(runtime: Runtime, host: str = "127.0.0.1", port: int = 8484):
    """Start the web server alongside the runtime."""
    server = WebServer(runtime)
    runner = web.AppRunner(server.app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    return runner
