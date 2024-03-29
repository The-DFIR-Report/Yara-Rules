/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-06-09
Identifier: Case 3930 From Word to Lateral Movement in 1 Hour
Reference: https://thedfirreport.com/2021/06/20/from-word-to-lateral-movement-in-1-hour/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule icedid_upefkuin4_3930 {
meta:
description = "3930 - file upefkuin4.dll"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-06-09"
hash1 = "666570229dd5af87fede86b9191fb1e8352d276a8a32c42e4bf4128a4f7e8138"
strings:
$s1 = "UAWAVAUATVWSH" fullword ascii
$s2 = "AWAVAUATVWUSH" fullword ascii
$s3 = "AWAVATVWUSH" fullword ascii
$s4 = "update" fullword ascii /* Goodware String - occured 207 times */
$s5 = "?ortpw@@YAHXZ" fullword ascii
$s6 = "?sortyW@@YAHXZ" fullword ascii
$s7 = "?sorty@@YAHXZ" fullword ascii
$s8 = "?keptyu@@YAHXZ" fullword ascii
$s9 = "*=UUUUr#L" fullword ascii
$s10 = "*=UUUUr!" fullword ascii
$s11 = "PluginInit" fullword ascii
$s12 = "*=UUUUr\"" fullword ascii
$s13 = "AVVWSH" fullword ascii
$s14 = "D$4iL$ " fullword ascii
$s15 = "X[]_^A\\A]A^A_" fullword ascii
$s16 = "D$4iT$ " fullword ascii
$s17 = "H[]_^A\\A]A^A_" fullword ascii
$s18 = "L94iL$ " fullword ascii
$s19 = "D$ iD$ " fullword ascii
$s20 = "*=UUUUr " fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 700KB and
( pe.imphash() == "87bed5a7cba00c7e1f4015f1bdae2183" and ( pe.exports("?keptyu@@YAHXZ") and pe.exports("?ortpw@@YAHXZ") and pe.exports("?sorty@@YAHXZ") and pe.exports("?sortyW@@YAHXZ") and pe.exports("PluginInit") and pe.exports("update") ) or 8 of them )
}

rule icedid_license_3930 {
meta:
description = "3930 - file license.dat"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-06-09"
hash1 = "29d2a8344bd725d7a8b43cc77a82b3db57a5226ce792ac4b37e7f73ec468510e"
strings:
$s1 = "iEQc- A1h" fullword ascii
$s2 = "%n%DLj" fullword ascii
$s3 = "n{Y@.hnPP#5\"~" fullword ascii
$s4 = "(5N&#jUBE\"0" fullword ascii
$s5 = "~JCyP+Av" fullword ascii
$s6 = "iLVIy\\" fullword ascii
$s7 = "RemwDVL" fullword ascii
$s8 = "EQiH^,>A" fullword ascii
$s9 = "#wmski;H" fullword ascii
$s10 = "aHVAh}X" fullword ascii
$s11 = "GEKK/no" fullword ascii
$s12 = "focbZjQ" fullword ascii
$s13 = "wHsJJX>e" fullword ascii
$s14 = "cYRS:F#" fullword ascii
$s15 = "EfNO\"h{" fullword ascii
$s16 = "akCevJ]" fullword ascii
$s17 = "8IMwwm}!" fullword ascii
$s18 = "NrzMP?<>" fullword ascii
$s19 = ".ZNrzLrU" fullword ascii
$s20 = "sJlCJP[" fullword ascii
condition:
uint16(0) == 0x02ee and filesize < 1000KB and
8 of them
}

rule icedid_win_01 {

meta:

description = "Detects Icedid" 
author = "The DFIR Report" 
date = "15/05/2021" 
description = "Detects Icedid functionality. incl. credential access, OS cmds." 
sha1 = "3F06392AF1687BD0BF9DB2B8B73076CAB8B1CBBA" 
score = 100

strings: 
$s1 = "DllRegisterServer" wide ascii fullword 
$x1 = "passff.tar" wide ascii fullword 
$x2 = "vaultcli.dll" wide ascii fullword 
$x3 = "cookie.tar" wide ascii fullword 
$y1 = "powershell.exe" wide ascii fullword 
$y2 = "cmd.exe" wide ascii fullword

condition:

( uint16(0) == 0x5a4d and int32(uint32(0x3c)) == 0x00004550 and filesize < 500KB and $s1 and ( 2 of ($x*) and 2 of ($y*))) 
}


rule fake_gzip_bokbot_202104 {

meta:

author = "Thomas Barabosch, Telekom Security" 
date = "2021-04-20" 
description = "fake gzip provided by CC"

strings:

$gzip = {1f 8b 08 08 00 00 00 00 00 00 75 70 64 61 74 65}

condition:

$gzip at 0

}

rule win_iceid_gzip_ldr_202104 {

meta:

author = "Thomas Barabosch, Telekom Security" 
date = "2021-04-12" 
description = "2021 initial Bokbot / Icedid loader for fake GZIP payloads"

strings:

$internal_name = "loader_dll_64.dll" fullword

$string0 = "_gat=" wide 
$string1 = "_ga=" wide 
$string2 = "_gid=" wide 
$string3 = "_u=" wide 
$string4 = "_io=" wide 
$string5 = "GetAdaptersInfo" fullword 
$string6 = "WINHTTP.dll" fullword 
$string7 = "DllRegisterServer" fullword 
$string8 = "PluginInit" fullword 
$string9 = "POST" wide fullword 
$string10 = "aws.amazon.com" wide fullword

condition:

uint16(0) == 0x5a4d and 
filesize < 5000KB and 
( $internal_name or all of ($s*) ) 
or all of them

}

rule win_iceid_core_ldr_202104 {

meta:

author = "Thomas Barabosch, Telekom Security" 
date = "2021-04-13" 
description = "2021 loader for Bokbot / Icedid core (license.dat)"

strings: 
$internal_name = "sadl_64.dll" fullword 
$string0 = "GetCommandLineA" fullword 
$string1 = "LoadLibraryA" fullword 
$string2 = "ProgramData" fullword 
$string3 = "SHLWAPI.dll" fullword 
$string4 = "SHGetFolderPathA" fullword 
$string5 = "DllRegisterServer" fullword 
$string6 = "update" fullword 
$string7 = "SHELL32.dll" fullword 
$string8 = "CreateThread" fullword

condition:

uint16(0) == 0x5a4d and 
filesize < 5000KB and 
( $internal_name or all of ($s*) ) 
or all of them

}

rule win_iceid_core_202104 {

meta: 
author = "Thomas Barabosch, Telekom Security" 
date = "2021-04-12" 
description = "2021 Bokbot / Icedid core"

strings:

$internal_name = "fixed_loader64.dll" fullword

$string0 = "mail_vault" wide fullword 
$string1 = "ie_reg" wide fullword 
$string2 = "outlook" wide fullword 
$string3 = "user_num" wide fullword 
$string4 = "cred" wide fullword 
$string5 = "Authorization: Basic" fullword 
$string6 = "VaultOpenVault" fullword 
$string7 = "sqlite3_free" fullword 
$string8 = "cookie.tar" fullword 
$string9 = "DllRegisterServer" fullword 
$string10 = "PT0S" wide

condition:

uint16(0) == 0x5a4d and 
filesize < 5000KB and 
( $internal_name or all of ($s*) ) 
or all of them

}
