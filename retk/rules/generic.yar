/*
 * Generic, low-confidence triage rules bundled with retk.
 * These flag *indicators worth a human look*, not confirmed malware —
 * every legitimate installer/game-anticheat/DRM tool also trips several
 * of these. Use them as a prioritization hint, never as a verdict.
 */

rule Possible_UPX_Packed
{
    meta:
        description = "UPX packer signature present"
    strings:
        $upx1 = "UPX0"
        $upx2 = "UPX1"
        $upx3 = "UPX!"
    condition:
        any of them
}

rule Possible_AntiDebug_AntiVM
{
    meta:
        description = "Strings commonly used for anti-debug/anti-VM checks"
    strings:
        $a1 = "IsDebuggerPresent"
        $a2 = "CheckRemoteDebuggerPresent"
        $a3 = "VMware" nocase
        $a4 = "VBoxGuest" nocase
        $a5 = "SbieDll" nocase
        $a6 = "SeDebugPrivilege"
    condition:
        any of them
}

rule Possible_Ransomware_Behavior_Strings
{
    meta:
        description = "Strings associated with ransomware-style file destruction/encryption behavior"
    strings:
        $s1 = "vssadmin delete shadows" nocase
        $s2 = "wbadmin delete catalog" nocase
        $s3 = "bcdedit /set" nocase
        $s4 = ".onion"
        $s5 = "your files have been encrypted" nocase
        $s6 = "README_FOR_DECRYPT" nocase
    condition:
        any of them
}

rule Possible_C2_Or_Exfil_Indicators
{
    meta:
        description = "Strings commonly seen in C2/exfil-capable malware"
    strings:
        $c1 = "cmd.exe /c" nocase
        $c2 = "powershell -enc" nocase
        $c3 = "User-Agent: Mozilla" nocase
        $c4 = "Content-Disposition: form-data"
        $c5 = "/gate.php"
        $c6 = "/panel/"
    condition:
        any of them
}

rule Possible_Credential_Theft_Indicators
{
    meta:
        description = "Strings associated with credential/browser-data theft"
    strings:
        $b1 = "Login Data" nocase
        $b2 = "\\Mozilla\\Firefox\\Profiles" nocase
        $b3 = "SELECT * FROM logins" nocase
        $b4 = "CRYPTPROTECT_PROMPT_ON_UNPROTECT"
    condition:
        any of them
}
