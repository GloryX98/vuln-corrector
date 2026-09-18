#!/usr/bin/env python3
"""
Browser front-end for vuln_corrector.

A tiny standard-library web server (no Flask): upload a Nessus/Tenable findings
sheet in the browser, it runs the same Tenable/NVD correction logic server-side
(the browser cannot call Tenable directly because of CORS), shows a live progress
bar and a change table, and lets you download the corrected sheet.

Run:
    python webui.py              # opens the browser on an uncommon local port
    python webui.py --port 9000 --host 0.0.0.0

Only the Python 3 standard library is required for CSV; .xlsx also needs openpyxl.
"""
from __future__ import annotations
import argparse
import csv
import io
import json
import os
import re
import sys
import threading
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# import the CLI module that lives next to this file (works frozen or from source)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vuln_corrector as vc  # noqa: E402

# Uncommon fixed local port: not a well-known service, and below 49152 so it
# avoids the dynamic range Windows reserves for Hyper-V/WinNAT.
DEFAULT_PORT = 43117
MAX_UPLOAD = 30 * 1024 * 1024   # 30 MB
JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()

import base64 as _b64  # noqa: E402

# Brand mark: a shield with a check — a security finding, corrected/verified.
LOGO_SVG = (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' aria-hidden='true'>"
    "<path d='M12 2 3.9 5.1v6.2c0 4.9 3.4 8.6 8.1 10.5 4.7-1.9 8.1-5.6 8.1-10.5V5.1z' fill='#61afef'/>"
    "<path d='M8.1 12.2l2.7 2.7 5.1-5.4' fill='none' stroke='#1b1f27' stroke-width='2.3'"
    " stroke-linecap='round' stroke-linejoin='round'/></svg>"
)
# Drop-zone glyph: a spreadsheet/document with an up-arrow (upload a sheet).
DROP_SVG = (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='#61afef'"
    " stroke-width='1.6' stroke-linecap='round' stroke-linejoin='round' aria-hidden='true'>"
    "<path d='M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z'/>"
    "<path d='M14 3v5h5'/><path d='M12 17.5v-6'/><path d='M9.5 14l2.5-2.5 2.5 2.5'/></svg>"
)
FAVICON = "data:image/svg+xml;base64," + _b64.b64encode(LOGO_SVG.encode("utf-8")).decode("ascii")

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vuln Rating & CVSS Corrector</title>
<link rel="icon" href="__FAVICON__">
<style>
:root{--bg:#282c34;--panel:#21252b;--panel2:#2c313a;--line:#3b414d;--fg:#dcdfe4;--mut:#828997;
--accent:#61afef;--accent-ink:#1b1f27;--crit:#e06c75;--high:#e5926a;--med:#e5c07b;--low:#98c379;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:Montserrat,'Segoe UI',system-ui,sans-serif;
font-size:14px;line-height:1.45}
.wrap{max-width:760px;margin:0 auto;padding:40px 20px 64px}
.head{display:flex;align-items:center;gap:14px;margin-bottom:8px}
.logo{width:40px;height:40px;flex:0 0 auto;display:block}
.logo svg{width:100%;height:100%}
h1{font-size:22px;font-weight:600;margin:0}
.sub{color:var(--mut);margin:0 0 28px 54px}
.sub b{color:var(--fg);font-weight:600}

.uploader{margin:0 auto}
.drop{max-width:560px;margin:0 auto;display:flex;flex-direction:column;align-items:center;
border:2px dashed var(--line);border-radius:16px;padding:44px 32px;background:var(--panel);
text-align:center;transition:.15s;cursor:pointer}
.drop.hot{border-color:var(--accent);background:var(--panel2)}
.drop .glyph{width:56px;height:56px;margin-bottom:16px}
.drop .glyph svg{width:100%;height:100%}
.drop .big{font-size:16px;margin:0 0 6px;color:var(--fg)}
.drop .hint{font-size:12.5px;color:var(--mut);margin:0}
.or{display:flex;align-items:center;gap:12px;color:var(--mut);font-size:11px;letter-spacing:1px;
width:180px;margin:22px 0}
.or::before,.or::after{content:"";flex:1;height:1px;background:var(--line)}
.browse{background:var(--accent);color:var(--accent-ink);border:0;border-radius:10px;
padding:11px 26px;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit}
.fname{margin:18px 0 0;color:var(--fg);font-weight:600;font-size:13px;word-break:break-all}
input[type=file]{display:none}

.actions{display:flex;justify-content:center;align-items:center;gap:12px;margin-top:24px;flex-wrap:wrap}
button{background:var(--accent);color:var(--accent-ink);border:0;border-radius:10px;padding:11px 24px;
font-size:14px;font-weight:600;cursor:pointer;font-family:inherit}
button:disabled{opacity:.45;cursor:not-allowed}
.note{color:var(--mut);font-size:12.5px}
.bar{height:8px;background:var(--panel2);border-radius:6px;overflow:hidden;margin-top:22px}
.bar > i{display:block;height:100%;width:0;background:var(--accent);transition:width .3s}
.status{color:var(--mut);margin-top:8px;font-size:13px;min-height:18px;text-align:center}
table{border-collapse:collapse;width:100%;margin-top:22px;font-size:13px}
th{text-align:left;color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.5px;
padding:8px 10px;border-bottom:1px solid var(--line)}
td{padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
.rf{font-weight:600;padding:1px 7px;border-radius:5px;font-size:11px}
.rf-Critical{background:rgba(224,108,117,.16);color:var(--crit)}
.rf-High{background:rgba(229,146,106,.16);color:var(--high)}
.rf-Medium{background:rgba(229,192,123,.14);color:var(--med)}
.rf-Low{background:rgba(152,195,121,.14);color:var(--low)}
.arrow{color:var(--mut);margin:0 4px}
.err{color:var(--crit);margin-top:16px;white-space:pre-wrap;text-align:center}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px;margin-top:24px}
.muted{color:var(--mut)}
a.dl{display:inline-block;text-decoration:none}
</style></head><body><div class="wrap">
<div class="head"><span class="logo">__LOGO__</span>
<h1>Vuln Rating &amp; CVSS Corrector</h1></div>
<div class="sub">Corrects the <b>Vulnerability Rating</b> and <b>CVSS</b> columns of a Nessus/Tenable
findings sheet (.csv or .xlsx) from Tenable (NVD fallback) and leaves everything else untouched.</div>

<div class="uploader">
  <div class="drop" id="drop">
    <span class="glyph">__DROPICON__</span>
    <p class="big"><b>Drop your sheet here</b> to start</p>
    <p class="hint">.csv or .xlsx &middot; nothing is stored on the server after download</p>
    <div class="or"><span>OR</span></div>
    <button type="button" class="browse" id="browse">Browse files</button>
    <p class="fname" id="fname"></p>
  </div>
  <input type="file" id="file" accept=".csv,.xlsx,.xlsm">
</div>

<div class="actions">
  <button id="go" disabled>Correct sheet</button>
  <span class="note" id="hint">Needs internet — it queries tenable.com / nvd.nist.gov.</span>
</div>

<div id="progress" style="display:none">
  <div class="bar"><i id="fill"></i></div>
  <div class="status" id="statusText"></div>
</div>

<div id="err" class="err"></div>

<div id="result" class="card" style="display:none">
  <div class="row" style="margin-top:0;justify-content:space-between">
    <div><b id="summary"></b></div>
    <a class="dl" id="dl"><button>Download corrected sheet</button></a>
  </div>
  <div id="tableWrap"></div>
</div>

<script>
var file=null, jobId=null, poll=null;
var drop=document.getElementById('drop'), fileInput=document.getElementById('file'),
    go=document.getElementById('go'), fname=document.getElementById('fname'),
    prog=document.getElementById('progress'), fill=document.getElementById('fill'),
    statusText=document.getElementById('statusText'), err=document.getElementById('err'),
    result=document.getElementById('result'), summary=document.getElementById('summary'),
    dl=document.getElementById('dl'), tableWrap=document.getElementById('tableWrap');

var browse=document.getElementById('browse');
function pick(f){ file=f; fname.textContent=f?('Selected: '+f.name):''; go.disabled=!f; }
fileInput.onchange=function(){ pick(fileInput.files[0]); };
browse.onclick=function(ev){ ev.stopPropagation(); fileInput.click(); };
drop.addEventListener('click',function(){ fileInput.click(); });
['dragover','dragenter'].forEach(function(e){drop.addEventListener(e,function(ev){ev.preventDefault();drop.classList.add('hot');});});
['dragleave','drop'].forEach(function(e){drop.addEventListener(e,function(ev){ev.preventDefault();drop.classList.remove('hot');});});
drop.addEventListener('drop',function(ev){ if(ev.dataTransfer.files.length) pick(ev.dataTransfer.files[0]); });

function esc(s){ return (s==null?'':String(s)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function rf(v){ return v?('<span class="rf rf-'+esc(v)+'">'+esc(v)+'</span>'):'<span class="muted">&mdash;</span>'; }

go.onclick=function(){
  if(!file) return;
  err.textContent=''; result.style.display='none'; go.disabled=true;
  prog.style.display='block'; fill.style.width='3%'; statusText.textContent='Uploading…';
  var fd=new FormData(); fd.append('file',file);
  fetch('/process',{method:'POST',body:fd}).then(function(r){return r.json();}).then(function(j){
    if(j.error){ fail(j.error); return; }
    jobId=j.job_id; poll=setInterval(checkStatus,900); checkStatus();
  }).catch(function(e){ fail(String(e)); });
};

function checkStatus(){
  fetch('/status/'+jobId).then(function(r){return r.json();}).then(function(s){
    if(s.state==='error'){ clearInterval(poll); fail(s.error||'Processing failed'); return; }
    var pct = s.total? Math.round(100*s.done/s.total):5;
    fill.style.width=Math.max(pct,5)+'%';
    statusText.textContent='Looking up '+s.done+' / '+s.total+(s.current?('  —  '+s.current):'');
    if(s.state==='done'){ clearInterval(poll); finish(s); }
  }).catch(function(e){ clearInterval(poll); fail(String(e)); });
}

function finish(s){
  fill.style.width='100%'; statusText.textContent='Done.';
  go.disabled=false; result.style.display='block';
  summary.textContent=s.changed+' finding'+(s.changed===1?'':'s')+' changed of '+s.total+' distinct.';
  dl.href='/download/'+jobId;
  if(!s.changes.length){ tableWrap.innerHTML='<p class="muted">No corrections were needed — everything already matched Tenable.</p>'; return; }
  var h='<table><thead><tr><th>Finding</th><th>Rating</th><th>CVSS</th><th>Rows</th><th>Source</th></tr></thead><tbody>';
  s.changes.forEach(function(c){
    h+='<tr><td>'+esc(c.title)+'</td><td>'+rf(c.old_rating)+'<span class="arrow">→</span>'+rf(c.new_rating)+
       '</td><td>'+esc(c.old_cvss)+'<span class="arrow">→</span><b>'+esc(c.new_cvss)+'</b></td><td>'+c.count+'</td><td class="muted">'+esc(c.source)+'</td></tr>';
  });
  tableWrap.innerHTML=h+'</tbody></table>';
}
function fail(m){ prog.style.display='none'; go.disabled=false; err.textContent='Error: '+m; }
</script>
</div></body></html>
"""

PAGE = (PAGE.replace("__FAVICON__", FAVICON)
            .replace("__LOGO__", LOGO_SVG)
            .replace("__DROPICON__", DROP_SVG))


def parse_multipart(body: bytes, boundary: bytes):
    """Minimal multipart/form-data parser -> {field_name: (filename, bytes)}."""
    out = {}
    delim = b"--" + boundary
    for part in body.split(delim):
        if part in (b"", b"--", b"--\r\n", b"\r\n"):
            continue
        if part.startswith(b"\r\n"):
            part = part[2:]
        if part.endswith(b"\r\n"):
            part = part[:-2]
        if b"\r\n\r\n" not in part:
            continue
        head, data = part.split(b"\r\n\r\n", 1)
        headtxt = head.decode("utf-8", "replace")
        mname = re.search(r'name="([^"]*)"', headtxt)
        mfile = re.search(r'filename="([^"]*)"', headtxt)
        if not mname:
            continue
        out[mname.group(1)] = (mfile.group(1) if mfile else None, data)
    return out


def run_job(job_id: str, filename: str, data: bytes):
    job = JOBS[job_id]
    tmp_in = None
    tmp_out = None
    try:
        ext = os.path.splitext(filename or "")[1].lower() or ".csv"
        is_xlsx = ext in (".xlsx", ".xlsm")
        base = os.path.join(os.environ.get("TEMP", "/tmp"), "vc_" + job_id)
        tmp_in = base + ext
        tmp_out = base + "_corrected" + ext
        with open(tmp_in, "wb") as fh:
            fh.write(data)

        if is_xlsx:
            rows, header, wb, ws = vc.read_xlsx(tmp_in)
            fieldnames = header
        else:
            rows, fieldnames = vc.read_csv(tmp_in)

        tcol = vc.detect_col(fieldnames, vc.TITLE_KEYS)
        rcol = vc.detect_col(fieldnames, vc.RATING_KEYS)
        ccol = vc.detect_col(fieldnames, vc.CVSS_KEYS)
        vcol = vc.detect_col(fieldnames, vc.CVE_KEYS)
        if not (tcol and rcol and ccol):
            raise ValueError(f"Could not find the needed columns (title={tcol}, rating={rcol}, cvss={ccol}). "
                             "Make sure the sheet has vulnerability-name, rating and CVSS columns.")

        distinct = {}
        for row in rows:
            distinct.setdefault(str(row.get(tcol, "")).strip(), str(row.get(vcol, "")) if vcol else "")
        distinct.pop("", None)
        job["total"] = len(distinct)

        resolved = {}
        for i, (title, cve_field) in enumerate(distinct.items(), 1):
            job["current"] = title
            job["done"] = i - 1
            resolved[title] = vc.resolve_finding(title, cve_field)
            job["done"] = i
            time.sleep(0.2)   # be polite to the servers

        # aggregate change display by title
        agg = {}
        for row in rows:
            title = str(row.get(tcol, "")).strip()
            base_s, sev, src = resolved.get(title, (None, None, "not found"))
            if base_s is None or sev in ("None", "Unknown"):
                continue
            new_rating = sev
            new_cvss = str(vc.clamped_integer(base_s, sev))
            old_rating = str(row.get(rcol, ""))
            old_cvss = str(row.get(ccol, ""))
            if old_rating != new_rating or old_cvss != new_cvss:
                row[rcol] = new_rating
                row[ccol] = new_cvss
                key = (title, old_rating, new_rating, old_cvss, new_cvss, src)
                agg[key] = agg.get(key, 0) + 1

        if is_xlsx:
            vc.write_xlsx_inplace(wb, ws, header, rows, (rcol, ccol))
            wb.save(tmp_out)
        else:
            vc.write_csv(tmp_out, rows, fieldnames)

        with open(tmp_out, "rb") as fh:
            result_bytes = fh.read()

        changes = [{"title": k[0], "old_rating": k[1], "new_rating": k[2],
                    "old_cvss": k[3], "new_cvss": k[4], "source": k[5], "count": n}
                   for k, n in sorted(agg.items(), key=lambda kv: kv[0][0])]
        stem = os.path.splitext(os.path.basename(filename or "findings"))[0]
        job.update(state="done", changes=changes, changed=len(changes),
                   result_bytes=result_bytes,
                   result_name=f"{stem}_corrected{ext}",
                   result_mime=("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                                if is_xlsx else "text/csv"))
    except Exception as e:  # noqa: BLE001
        job.update(state="error", error=str(e))
    finally:
        for p in (tmp_in, tmp_out):
            try:
                if p and os.path.exists(p):
                    os.remove(p)
            except OSError:
                pass


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quieter console
        pass

    def _send(self, code, body, ctype="application/json", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            self._send(200, PAGE, "text/html; charset=utf-8")
        elif self.path.startswith("/status/"):
            jid = self.path.rsplit("/", 1)[-1]
            job = JOBS.get(jid)
            if not job:
                self._send(404, json.dumps({"error": "unknown job"}))
                return
            self._send(200, json.dumps({k: job.get(k) for k in
                       ("state", "done", "total", "current", "changes", "changed", "error")}))
        elif self.path.startswith("/download/"):
            jid = self.path.rsplit("/", 1)[-1]
            job = JOBS.get(jid)
            if not job or job.get("state") != "done":
                self._send(404, "not ready", "text/plain")
                return
            self._send(200, job["result_bytes"], job["result_mime"],
                       {"Content-Disposition": f'attachment; filename="{job["result_name"]}"'})
        else:
            self._send(404, "not found", "text/plain")

    def do_POST(self):
        if self.path != "/process":
            self._send(404, json.dumps({"error": "not found"}))
            return
        ctype = self.headers.get("Content-Type", "")
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0 or length > MAX_UPLOAD:
            self._send(413, json.dumps({"error": "file too large or empty (max 30 MB)"}))
            return
        m = re.search(r"boundary=(.+)$", ctype)
        if "multipart/form-data" not in ctype or not m:
            self._send(400, json.dumps({"error": "expected a file upload"}))
            return
        boundary = m.group(1).strip('"').encode("utf-8")
        body = self.rfile.read(length)
        fields = parse_multipart(body, boundary)
        if "file" not in fields or not fields["file"][1]:
            self._send(400, json.dumps({"error": "no file received"}))
            return
        filename, data = fields["file"]
        job_id = uuid.uuid4().hex
        with JOBS_LOCK:
            JOBS[job_id] = {"state": "running", "done": 0, "total": 0, "current": "", "changes": []}
        threading.Thread(target=run_job, args=(job_id, filename, data), daemon=True).start()
        self._send(200, json.dumps({"job_id": job_id}))


def main():
    ap = argparse.ArgumentParser(description="Browser UI for vuln_corrector.")
    # Defaults honour the PORT/HOST env vars used by most hosting platforms.
    ap.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", str(DEFAULT_PORT))))
    ap.add_argument("--no-open", action="store_true", help="do not open a browser automatically")
    args = ap.parse_args()
    # When bound to all interfaces (containers/hosts) don't try to open a browser.
    if args.host in ("0.0.0.0", "") or os.environ.get("PORT"):
        args.no_open = True

    # Bind the chosen port; if it (and its neighbours) are busy or reserved,
    # fall back to an OS-assigned free port so the app always starts.
    srv = None
    port = args.port
    for p in list(range(args.port, args.port + 25)) + [0]:
        try:
            srv = ThreadingHTTPServer((args.host, p), Handler)
            port = srv.server_address[1]
            break
        except OSError:
            continue
    if srv is None:
        sys.exit("Could not bind any local port. Try --port <number>.")

    shown_host = "127.0.0.1" if args.host in ("0.0.0.0", "") else args.host
    url = f"http://{shown_host}:{port}"
    print(f"Vuln Corrector is running.  Open {url} in your browser.  (Ctrl+C to stop)", flush=True)
    if not args.no_open:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
