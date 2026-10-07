/*
   Built-in YARA rules used to describe supplied samples.  They flag well known
   traits, not verdicts.  Add your own .yar files next to this one or supply them
   per case in the New Case wizard.
*/

rule WFA_UPX_Packed
{
    meta: description = "Packed with UPX"
    strings: $a = "UPX0" $b = "UPX1" $c = "UPX!"
    condition: uint16(0) == 0x5A4D and 2 of them
}

rule WFA_Mimikatz_Strings
{
    meta: description = "Mimikatz credential dumping tool strings"
    strings:
        $a = "sekurlsa::logonpasswords" ascii wide nocase
        $b = "lsadump::sam" ascii wide nocase
        $c = "gentilkiwi" ascii wide nocase
        $d = "mimikatz" ascii wide nocase
    condition: 2 of them
}

rule WFA_CobaltStrike_Beacon_Strings
{
    meta: description = "Strings typical of Cobalt Strike beacons / stagers"
    strings:
        $a = "%s as %s\\%s: %d" ascii
        $b = "beacon.dll" ascii nocase
        $c = "ReflectiveLoader" ascii
        $d = "%02d/%02d/%02d %02d:%02d:%02d" ascii
        $e = "could not spawn %s: %d" ascii
    condition: 2 of them
}

rule WFA_PowerShell_Download_Cradle
{
    meta: description = "PowerShell download-and-execute cradle"
    strings:
        $a = "DownloadString" ascii wide nocase
        $b = "Net.WebClient" ascii wide nocase
        $c = "IEX" ascii wide
        $d = "Invoke-Expression" ascii wide nocase
        $e = "FromBase64String" ascii wide nocase
        $f = "-EncodedCommand" ascii wide nocase
    condition: 2 of them
}

rule WFA_Ransom_Note_Language
{
    meta: description = "Ransom note wording"
    strings:
        $a = "your files have been encrypted" ascii wide nocase
        $b = "decryption key" ascii wide nocase
        $c = "bitcoin" ascii wide nocase
        $d = ".onion" ascii wide nocase
        $e = "restore your files" ascii wide nocase
    condition: 2 of them
}

rule WFA_Shadow_Copy_Deletion
{
    meta: description = "Shadow copy / backup deletion commands"
    strings:
        $a = "vssadmin delete shadows" ascii wide nocase
        $b = "shadowcopy delete" ascii wide nocase
        $c = "wbadmin delete catalog" ascii wide nocase
        $d = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
    condition: any of them
}

rule WFA_AutoIt_Compiled
{
    meta: description = "Compiled AutoIt script (often used by loaders)"
    strings: $a = "AU3!EA06" ascii $b = ">>>AUTOIT SCRIPT<<<" ascii wide
    condition: any of them
}

rule WFA_Office_AutoExec_Macro
{
    meta: description = "Office macro that runs automatically"
    strings:
        $a = "AutoOpen" ascii wide nocase
        $b = "Document_Open" ascii wide nocase
        $c = "Workbook_Open" ascii wide nocase
        $v = "VBA" ascii wide
    condition: $v and any of ($a, $b, $c)
}

rule WFA_Infostealer_Browser_Targets
{
    meta: description = "References to browser credential / cookie stores and crypto wallets (info-stealer behavior)"
    strings:
        $a = "\\Google\\Chrome\\User Data" ascii wide nocase
        $b = "Login Data" ascii wide
        $c = "\\Mozilla\\Firefox\\Profiles" ascii wide nocase
        $d = "wallet.dat" ascii wide nocase
        $e = "Local State" ascii wide
        $f = "logins.json" ascii wide
    condition: 3 of them
}

rule WFA_Telegram_Discord_Exfil
{
    meta: description = "Exfiltration through Telegram bot API or Discord webhooks"
    strings:
        $a = "api.telegram.org/bot" ascii wide nocase
        $b = "discord.com/api/webhooks" ascii wide nocase
        $c = "discordapp.com/api/webhooks" ascii wide nocase
    condition: any of them
}
