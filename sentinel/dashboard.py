"""Local dashboard: standard-library HTTP server, bound to 127.0.0.1, GET-only, opens the database read-only."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

from .store import Store

PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>SentinelGuard</title>
<style>body{font:15px system-ui;margin:2rem;max-width:1000px}h1{margin:0}.c{display:flex;gap:1rem;margin:1rem 0}
.k{padding:.6rem 1rem;border-radius:8px;background:#eef2fa}table{border-collapse:collapse;width:100%}
td,th{border-bottom:1px solid #ddd;padding:.4rem;text-align:left;vertical-align:top}
.critical{color:#b00020;font-weight:700}.high{color:#d84315}.medium{color:#b8860b}.low{color:#0277bd}</style></head>
<body><h1>SentinelGuard</h1><div id="s" class="c"></div><table><thead><tr><th>Severity</th><th>Issue</th><th>Where</th><th>Fix</th></tr></thead><tbody id="t"></tbody></table>
<script>
const td=(t,c)=>{const e=document.createElement('td');e.textContent=t;if(c)e.className=c;return e};
fetch('/api/summary').then(r=>r.json()).then(s=>{const d=document.getElementById('s');
 for(const [k,v] of Object.entries(s.open)){const e=document.createElement('div');e.className='k';e.textContent=k+': '+v;d.appendChild(e)}});
fetch('/api/findings').then(r=>r.json()).then(fs=>{const b=document.getElementById('t');
 for(const f of fs){const r=document.createElement('tr');r.append(td(f.severity,f.severity),td(f.rule_id+' '+f.message),td(f.path+(f.line?':'+f.line:'')),td(f.fix));b.appendChild(r)}});
</script></body></html>"""


def serve(state_dir, host="127.0.0.1", port=8787):
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("Refusing to bind to a non-loopback address.")

    class H(BaseHTTPRequestHandler):
        def _send(self, body: bytes, ctype: str):
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            st = Store(state_dir, readonly=True)
            try:
                if self.path == "/api/summary":
                    s = st.summary()
                    self._send(json.dumps({"open": s["open"], "ignored": s["ignored"], "fixed": s["fixed"]}).encode(), "application/json")
                elif self.path == "/api/findings":
                    self._send(json.dumps([f.to_dict() for f in st.open_findings()]).encode(), "application/json")
                elif self.path in ("/", "/index.html"):
                    self._send(PAGE.encode(), "text/html; charset=utf-8")
                else:
                    self.send_error(404)
            finally:
                st.close()

        def log_message(self, *a):
            pass

    srv = HTTPServer((host, port), H)
    print(f"Dashboard on http://{host}:{port}  (read-only, local only, Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
