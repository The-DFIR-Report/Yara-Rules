/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-08-02
Identifier: Case 4641 BazarCall to Conti Ransomware via Trickbot and Cobalt Strike
Reference: https://thedfirreport.com/2021/08/01/bazarcall-to-conti-ransomware-via-trickbot-and-cobalt-strike/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule sig_4641_fQumH {
meta:
description = "4641 - file fQumH.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-08-02"
hash1 = "3420a0f6f0f0cc06b537dc1395638be0bffa89d55d47ef716408309e65027f31"
strings:
$s1 = "Usage: .system COMMAND" fullword ascii
$s2 = "Usage: .log FILENAME" fullword ascii
$s3 = "* If FILE begins with \"|\" then it is a command that generates the" fullword ascii
$s4 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s5 = "Usage %s sub-command ?switches...?" fullword ascii
$s6 = "attach debugger to process %d and press any key to continue." fullword ascii
$s7 = "%s:%d: expected %d columns but found %d - extras ignored" fullword ascii
$s8 = "%s:%d: expected %d columns but found %d - filling the rest with NULL" fullword ascii
$s9 = "Unknown option \"%s\" on \".dump\"" fullword ascii
$s10 = "REPLACE INTO temp.sqlite_parameters(key,value)VALUES(%Q,%s);" fullword ascii
$s11 = "error in %s %s%s%s: %s" fullword ascii
$s12 = "UPDATE temp.sqlite_master SET sql = sqlite_rename_column(sql, type, name, %Q, %Q, %d, %Q, %d, 1) WHERE type IN ('trigger', 'view" ascii
$s13 = "BBBBBBBBBBBBBBBBBBBB" wide /* reversed goodware string 'BBBBBBBBBBBBBBBBBBBB' */
$s14 = "UPDATE temp.sqlite_master SET sql = sqlite_rename_column(sql, type, name, %Q, %Q, %d, %Q, %d, 1) WHERE type IN ('trigger', 'view" ascii
$s15 = ");CREATE TEMP TABLE [_shell$self](op,cmd,ans);" fullword ascii
$s16 = "SqlExec" fullword ascii
$s17 = "* If neither --csv or --ascii are used, the input mode is derived" fullword ascii
$s18 = "Where sub-commands are:" fullword ascii
$s19 = "max rootpage (%d) disagrees with header (%d)" fullword ascii
$s20 = "-- Query %d --------------------------------" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 4000KB and
( pe.imphash() == "67f1f64a3db0d22bf48121a6cea1da22" or 8 of them )
}

rule sig_4641_62 {
meta:
description = "4641 - file 62.dll"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-08-02"
hash1 = "8b9d605b826258e07e63687d1cefb078008e1a9c48c34bc131d7781b142c84ab"
strings:
$s1 = "Common causes completion include incomplete download and damaged media" fullword ascii
$s2 = "An error occurred writing to the file" fullword ascii
$s3 = "asks should be performed?" fullword ascii
$s4 = "The waiting time for the end of the launch was exceeded for an unknown reason" fullword ascii
$s5 = "Select the Start Menu folder in which you would like Setup to create the programs shortcuts, then click Next. Which additional t" ascii
$s6 = "HcA<E3" fullword ascii /* Goodware String - occured 1 times */
$s7 = "Select the Start Menu folder in which you would like Setup to create the programs shortcuts, then click Next. Which additional t" ascii
$s8 = "D$(9D$@u" fullword ascii /* Goodware String - occured 1 times */
$s9 = "Please verify that the correct path and file name are given" fullword ascii
$s10 = "Critical error" fullword ascii
$s11 = "Please read this information carefully" fullword ascii
$s12 = "Unknown error occurred for time: " fullword ascii
$s13 = "E 3y4i" fullword ascii
$s14 = "D$tOuo2" fullword ascii
$s15 = "D$PH9D$8tXH" fullword ascii
$s16 = "E$hik7" fullword ascii
$s17 = "D$p]mjk" fullword ascii
$s18 = "B):0~\"Z" fullword ascii
$s19 = "Richo/" fullword ascii
$s20 = "D$xJij" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 70KB and
( pe.imphash() == "42205b145650671fa4469a6321ccf8bf" and pe.exports("StartW") or 8 of them )
}

rule sig_4641_tdrE934 {
meta:
description = "4641 - file tdrE934.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-08-02"
hash1 = "48f2e2a428ec58147a4ad7cc0f06b3cf7d2587ccd47bad2ea1382a8b9c20731c"
strings:
$s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s2 = "D:\\1W7w3cZ63gF\\wFIFSV\\YFU1GTi1\\i5G3cr\\Wb2f\\Cvezk3Oz\\2Zi9ir\\S76RW\\RE5kLijcf.pdb" fullword ascii
$s3 = "https://sectigo.com/CPS0" fullword ascii
$s4 = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii
$s5 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii
$s6 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii
$s7 = "ntdll.dlH" fullword ascii
$s8 = "http://ocsp.sectigo.com0" fullword ascii
$s9 = "2http://crl.sectigo.com/SectigoRSACodeSigningCA.crl0s" fullword ascii
$s10 = "2http://crt.sectigo.com/SectigoRSACodeSigningCA.crt0#" fullword ascii
$s11 = "tmnEt6XElyFyz2dg5EP4TMpAvGdGtork5EZcpw3eBwJQFABWlUZa5slcF6hqfGb2HgPed49gr2baBCLwRel8zM5cbMfsrOdS1yd6bMpepebebyT4NIN6zOvk" fullword ascii
$s12 = "ealagi@aol.com0" fullword ascii
$s13 = "operator co_await" fullword ascii
$s14 = "ZGetModuleHandle" fullword ascii
$s15 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
$s16 = "RtlExitUserThrea`NtFlushInstruct" fullword ascii
$s17 = "UAWAVAUATVWSH" fullword ascii
$s18 = "AWAVAUATVWUSH" fullword ascii
$s19 = "AWAVVWSH" fullword ascii
$s20 = "UAWAVATVWSH" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 2000KB and
( pe.imphash() == "4f1ec786c25f2d49502ba19119ebfef6" or 8 of them )
}

rule sig_4641_netscan {
meta:
description = "4641 - file netscan.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-08-02"
hash1 = "bb574434925e26514b0daf56b45163e4c32b5fc52a1484854b315f40fd8ff8d2"
strings:
$s1 = "netscan.exe" fullword ascii
$s2 = "TFMREMOTEPOWERSHELL" fullword wide
$s3 = "TFMREMOTEPOWERSHELLEDIT" fullword wide
$s4 = "TFMBASEDIALOGREMOTEEDIT" fullword wide
$s5 = "*http://crl4.digicert.com/assured-cs-g1.crl0L" fullword ascii
$s6 = "*http://crl3.digicert.com/assured-cs-g1.crl00" fullword ascii
$s7 = "TFMIGNOREADDRESS" fullword wide
$s8 = "TREMOTECOMMONFORM" fullword wide
$s9 = "TFMSTOPSCANDIALOG" fullword wide
$s10 = "TFMBASEDIALOGSHUTDOWN" fullword wide
$s11 = "TFMBASEDIALOG" fullword wide
$s12 = "TFMOFFLINEDIALOG" fullword wide
$s13 = "TFMLIVEDISPLAYLOG" fullword wide
$s14 = "TFMHOSTPROPS" fullword wide
$s15 = "GGG`BBB" fullword ascii /* reversed goodware string 'BBB`GGG' */
$s16 = "SoftPerfect Network Scanner" fullword wide
$s17 = "TUSERPROMPTFORM" fullword wide
$s18 = "TFMREMOTESSH" fullword wide
$s19 = "TFMREMOTEGROUPSEDIT" fullword wide
$s20 = "TFMREMOTEWMI" fullword wide
condition:
uint16(0) == 0x5a4d and filesize < 6000KB and
( pe.imphash() == "573e7039b3baff95751bded76795369e" and ( pe.exports("__dbk_fcall_wrapper") and pe.exports("dbkFCallWrapperAddr") ) or 8 of them )
}

rule sig_4641_tdr615 {
meta:
description = "4641 - file tdr615.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-08-02"
hash1 = "12761d7a186ff14dc55dd4f59c4e3582423928f74d8741e7ec9f761f44f369e5"
strings:
$s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s2 = "I:\\RoDcnyLYN\\k1GP\\ap0pivKfOF\\odudwtm30XMz\\UnWdqN\\01\\7aXg1kTkp.pdb" fullword ascii
$s3 = "https://sectigo.com/CPS0" fullword ascii
$s4 = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii
$s5 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii
$s6 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii
$s7 = "http://ocsp.sectigo.com0" fullword ascii
$s8 = "2http://crl.sectigo.com/SectigoRSACodeSigningCA.crl0s" fullword ascii
$s9 = "2http://crt.sectigo.com/SectigoRSACodeSigningCA.crt0#" fullword ascii
$s10 = "ealagi@aol.com0" fullword ascii
$s11 = "operator co_await" fullword ascii
$s12 = "GetModuleHandleRNtUnmapViewOfSe" fullword ascii
$s13 = "+GetProcAddress" fullword ascii
$s14 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
$s15 = "RtlExitUserThrebNtFlushInstruct" fullword ascii
$s16 = "Sectigo Limited1$0\"" fullword ascii
$s17 = "b<log10" fullword ascii
$s18 = "D*<W -" fullword ascii
$s19 = "WINDOWSPROJECT1" fullword wide
$s20 = "WindowsProject1" fullword wide
condition:
uint16(0) == 0x5a4d and filesize < 10000KB and
( pe.imphash() == "555560b7871e0ba802f2f6fbf05d9bfa" or 8 of them )
}

rule CS_DLL { 
meta: 
description = "62.dll" 
author = "The DFIR Report" 
reference = "https://thedfirreport.com" 
date = "2021-07-07" 
hash1 = "8b9d605b826258e07e63687d1cefb078008e1a9c48c34bc131d7781b142c84ab" 
strings: 
$s1 = "Common causes completion include incomplete download and damaged media" fullword ascii 
$s2 = "StartW" fullword ascii 
$s4 = ".rdata$zzzdbg" fullword ascii 
condition: 
uint16(0) == 0x5a4d and filesize < 70KB and ( pe.imphash() == "42205b145650671fa4469a6321ccf8bf" ) 
or (all of them) 
}


rule tdr615_exe { 
meta: 
description = "Cobalt Strike on beachhead: tdr615.exe" 
author = "The DFIR Report" 
reference = "https://thedfirreport.com" 
date = "2021-07-07" 
hash1 = "12761d7a186ff14dc55dd4f59c4e3582423928f74d8741e7ec9f761f44f369e5" 
strings: 
$a1 = "AppPolicyGetProcessTerminationMethod" fullword ascii 
$a2 = "I:\\RoDcnyLYN\\k1GP\\ap0pivKfOF\\odudwtm30XMz\\UnWdqN\\01\\7aXg1kTkp.pdb" fullword ascii 
$b1 = "ealagi@aol.com0" fullword ascii 
$b2 = "operator co_await" fullword ascii 
$b3 = "GetModuleHandleRNtUnmapViewOfSe" fullword ascii 
$b4 = "RtlExitUserThrebNtFlushInstruct" fullword ascii 
$c1 = "Jersey City1" fullword ascii 
$c2 = "Mariborska cesta 971" fullword ascii 
condition: 
uint16(0) == 0x5a4d and filesize < 10000KB and 
any of ($a* ) and 2 of ($b* ) and any of ($c* ) 
} 
