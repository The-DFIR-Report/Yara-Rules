/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-01-25
Identifier: Case 1013 Bazar, No Ryuk?
Reference: https://thedfirreport.com/2021/01/31/bazar-no-ryuk/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule bazar_start_bat {
meta:
description = "files - file start.bat"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-01-25"
hash1 = "63de40c7382bbfe7639f51262544a3a62d0270d259e3423e24415c370dd77a60"
strings:
$x1 = "powershell.exe Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force" fullword ascii
$x2 = "powershell.exe -executionpolicy remotesigned -File .\\Get-DataInfo.ps1 %1)" fullword ascii
$x3 = "powershell.exe -executionpolicy remotesigned -File .\\Get-DataInfo.ps1 %method" fullword ascii
$s4 = "set /p method=\"Press Enter for collect [all]: \"" fullword ascii
$s5 = "echo \"all ping disk soft noping nocompress\"" fullword ascii
$s6 = "echo \"Please select a type of info collected:\"" fullword ascii
$s7 = "@echo on" fullword ascii /* Goodware String - occured 1 times */
$s8 = "color 07" fullword ascii
$s9 = "pushd %~dp0" fullword ascii /* Goodware String - occured 1 times */
$s10 = "color 70" fullword ascii
$s11 = "IF \"%1\"==\"\" (" fullword ascii
$s12 = "IF NOT \"%1\"==\"\" (" fullword ascii
condition:
uint16(0) == 0x6540 and filesize < 1KB and
1 of ($x*) and all of them
}

rule bazar_M1E1626 {
meta:
description = "files - file M1E1626.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-01-25"
hash1 = "d362c83e5a6701f9ae70c16063d743ea9fe6983d0c2b9aa2c2accf2d8ba5cb38"
strings:
$s1 = "ResizeFormToFit.EXE" fullword wide
$s2 = "C:\\Windows\\explorer.exe" fullword ascii
$s3 = "bhart@pinpub.com" fullword wide
$s4 = "constructor or from DllMain." fullword ascii
$s5 = "dgsvhwe" fullword ascii
$s6 = "ResizeFormToFit.Document" fullword wide
$s7 = "ResizeFormToFit Version 1.0" fullword wide
$s8 = "This is a dummy form view for illustration of how to size the child frame window of the form to fit this form." fullword wide
$s9 = "GSTEAQR" fullword ascii
$s10 = "HTBNMRRTNSHNH" fullword ascii
$s11 = "RCWZCSJXRRNBL" fullword ascii
$s12 = "JFCNZXHXPTCT" fullword ascii
$s13 = "BLNEJPFAWFPU" fullword ascii
$s14 = "BREUORYYPKS" fullword ascii
$s15 = "UCWOJTPGLBZTI" fullword ascii
$s16 = "DZVVFAVZVWMVS" fullword ascii
$s17 = "MNKRAMLGWUX" fullword ascii
$s18 = "WHVMUKGVCHCT" fullword ascii
$s19 = "\\W\\TQPNIQWNZN" fullword ascii
$s20 = "ResizeFormToFit3" fullword wide
condition:
uint16(0) == 0x5a4d and filesize < 2000KB and
( pe.imphash() == "578738b5c4621e1bf95fce0a570a7cfc" or 8 of them )
}


rule bazar_files_netscan {
meta:
description = "files - file netscan.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-01-25"
hash1 = "ce6fc6cca035914a28bbc453ee3e8ef2b16a79afc01d8cb079c70c7aee0e693f"
strings:
$s1 = "TREMOTECOMMONFORM" fullword wide
$s2 = "ELHEADERRIGHTBMP" fullword wide
$s3 = "ELHEADERDESCBMP" fullword wide
$s4 = "ELHEADERLEFTBMP" fullword wide
$s5 = "ELHEADERASCBMP" fullword wide
$s6 = "ELHEADERPOINTBMP" fullword wide
$s7 = "<description>A free multithreaded IP, SNMP, NetBIOS scanner.</description>" fullword ascii
$s8 = "GGG`BBB" fullword ascii /* reversed goodware string 'BBB`GGG' */
$s9 = "name=\"SoftPerfect Network Scanner\"/>" fullword ascii
$s10 = "SoftPerfect Network Scanner" fullword wide
$s11 = "TREMOTESERVICEEDITFORM" fullword wide
$s12 = "TUSERPROMPTFORM" fullword wide
$s13 = "TREMOTEWMIFORM" fullword wide
$s14 = "TPUBLICIPFORM" fullword wide
$s15 = "TREMOTESERVICESFORM" fullword wide
$s16 = "TREMOTEWMIEDITFORM" fullword wide
$s17 = "TREMOTEFILEEDITFORM" fullword wide
$s18 = "TREMOTEREGISTRYFORM" fullword wide
$s19 = "TPASTEIPADDRESSFORM" fullword wide
$s20 = "TREMOTEREGISTRYEDITFORM" fullword wide
condition:
uint16(0) == 0x5a4d and filesize < 2000KB and
( pe.imphash() == "e9d20acdeaa8947f562cf14d3976522e" or 8 of them )
}
