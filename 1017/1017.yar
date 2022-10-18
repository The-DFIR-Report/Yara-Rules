/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-02-22
Identifier: Case 1017 Bazar Drops the Anchor
Reference: https://thedfirreport.com/2021/03/08/bazar-drops-the-anchor/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule bazar_14wfa5dfs {
meta:
description = "files - file 14wfa5dfs.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-02-22"
hash1 = "2065157b834e1116abdd5d67167c77c6348361e04a8085aa382909500f1bbe69"
strings:
$s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '' */
$s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '' */
$s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s4 = "0??dfg.dll ASHI128 bit 98tqewC58752F9578" fullword ascii
$s5 = "*http://crl4.digicert.com/assured-cs-g1.crl0L" fullword ascii
$s6 = "*http://crl3.digicert.com/assured-cs-g1.crl00" fullword ascii
$s7 = "/http://crl4.digicert.com/sha2-assured-cs-g1.crl0L" fullword ascii
$s8 = "appguid={8A69D345-D564-463C-AFF1-A69D9E530F96}&iid={F61A86A8-0045-3726-D207-E8A923987AD2}&lang=ru&browser=4&usagestats=1&appname" ascii
$s9 = "operator co_await" fullword ascii
$s10 = "appguid={8A69D345-D564-463C-AFF1-A69D9E530F96}&iid={F61A86A8-0045-3726-D207-E8A923987AD2}&lang=ru&browser=4&usagestats=1&appname" ascii
$s11 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
$s12 = "Google LLC1" fullword ascii
$s13 = "Google LLC0" fullword ascii
$s14 = "Unknown issuer0" fullword ascii
$s15 = "DigiCert, Inc.1$0\"" fullword ascii
$s16 = "=Google%20Chrome&needsadmin=prefers&ap=x64-stable-statsdef_1&installdataindex=empty" fullword ascii
$s17 = "TIMESTAMP-SHA256-2019-10-150" fullword ascii
$s18 = "vggwqrwqr7d6" fullword ascii
$s19 = "api-ms-win-core-file-l1-2-2" fullword wide /* Goodware String - occured 1 times */
$s20 = "__swift_2" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 3000KB and
( pe.imphash() == "d8af53b239700b702d462c81a96d396c" and all of them )
}

rule cobalt_strike_tmp01925d3f {
meta:
description = "files - file ~tmp01925d3f.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-02-22"
hash1 = "10ff83629d727df428af1f57c524e1eaddeefd608c5a317a5bfc13e2df87fb63"
strings:
$x1 = "C:\\Users\\hillary\\source\\repos\\gromyko\\Release\\gromyko.pdb" fullword ascii
$x2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */
$s3 = "gromyko32.dll" fullword ascii
$s4 = "<requestedExecutionLevel level='asInvoker' uiAccess='false'/>" fullword ascii
$s5 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s6 = "https://sectigo.com/CPS0" fullword ascii
$s7 = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii
$s8 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii
$s9 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii
$s10 = "http://ocsp.sectigo.com0" fullword ascii
$s11 = "2http://crl.sectigo.com/SectigoRSACodeSigningCA.crl0s" fullword ascii
$s12 = "2http://crt.sectigo.com/SectigoRSACodeSigningCA.crt0#" fullword ascii
$s13 = "http://www.digicert.com/CPS0" fullword ascii
$s14 = "AppPolicyGetThreadInitializationType" fullword ascii
$s15 = "alerajner@aol.com0" fullword ascii
$s16 = "gromyko.inf" fullword ascii
$s17 = "operator<=>" fullword ascii
$s18 = "operator co_await" fullword ascii
$s19 = "gromyko" fullword ascii
$s20 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
condition:
uint16(0) == 0x5a4d and filesize < 1000KB and
( pe.imphash() == "1b1b73382580c4be6fa24e8297e1849d" and ( 1 of ($x*) or all of them ) )
}

rule advanced_ip_scanner {
meta:
description = "files - file advanced_ip_scanner.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-02-22"
hash1 = "722fff8f38197d1449df500ae31a95bb34a6ddaba56834b13eaaff2b0f9f1c8b"
strings:
$x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><t" ascii
$s2 = "fo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAcce" ascii
$s3 = "Executable files (*.exe)" fullword ascii
$s4 = "0RolUpdater.dll" fullword wide
$s5 = "Qt5WinExtras.dll" fullword ascii
$s6 = "Radmin.exe" fullword ascii
$s7 = "ping.exe" fullword ascii
$s8 = "tracert.exe" fullword ascii
$s9 = "famatech.com" fullword ascii
$s10 = "advanced_ip_scanner.exe" fullword wide
$s11 = "Z:\\out\\Release\\NetUtils\\x86\\advanced_ip_scanner.pdb" fullword ascii
$s12 = "Qt5Xml.dll" fullword ascii
$s13 = "/telnet.exe" fullword ascii
$s14 = "onTargetScanned" fullword ascii
$s15 = "CScanTargetsShared" fullword ascii
$s16 = "1OnCmdScanSelected( CScanTargets& )" fullword ascii
$s17 = "http://www.advanced-ip-scanner.com/" fullword ascii
$s18 = "2CmdScanSelected( CScanTargets& )" fullword ascii
$s19 = "</style></head><body style=\" font-family:'MS Shell Dlg 2'; font-size:8.25pt; font-weight:400; font-style:normal;\">" fullword ascii
$s20 = "<a href=\"http://www.radmin.com\">www.radmin.com</a>" fullword wide
condition:
uint16(0) == 0x5a4d and filesize < 5000KB and
( pe.imphash() == "a3bc8eb6ac4320e91b7faf1e81af2bbf" or ( 1 of ($x*) or all of them ) )
}

rule anchor_x64 {
meta:
description = "files - file anchor_x64.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-02-22"
hash1 = "ca72600f50c76029b6fb71f65423afc44e4e2d93257c3f95fb994adc602f3e1b"
strings:
$x1 = "cmd.exe /c timeout 3 && " fullword wide
$x2 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo><security><requestedPrivileges><requeste" ascii
$x3 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */
$s4 = "\\System32\\cmd.ex\\System32\\rundllP" fullword ascii
$s5 = "Z:\\D\\GIT\\anchorDns.llvm\\Bin\\x64\\Release\\anchorDNS_x64.pdb" fullword ascii
$s6 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s7 = "cutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><appli" ascii
$s8 = "thExecute" fullword ascii
$s9 = "on xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSe" ascii
$s10 = "WinHTTP loader/1.0" fullword wide
$s11 = "AppPolicyGetThreadInitializationType" fullword ascii
$s12 = "AnchorDNS.cpp" fullword ascii
$s13 = "hardWorker.cpp" fullword ascii
$s14 = "operator<=>" fullword ascii
$s15 = "operator co_await" fullword ascii
$s16 = "/C PowerShell \"Start-Slemove-Iteep 3; Re" fullword wide
$s17 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo><security><requestedPrivileges><requeste" ascii
$s18 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
$s19 = "UAWAVAUATVWSH" fullword ascii
$s20 = "AWAVAUATVWUSH" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 1000KB and
( pe.imphash() == "e2450fb3cc5b1b7305e3193fe03f3369" and ( 1 of ($x*) or all of them ) )
}

rule anchorDNS_x64 {
meta:
description = "files - file anchorDNS_x64.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-02-22"
hash1 = "9fdbd76141ec43b6867f091a2dca503edb2a85e4b98a4500611f5fe484109513"
strings:
$x1 = "cmd.exe /c timeout 3 && " fullword wide
$x2 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo><security><requestedPrivileges><requeste" ascii
$x3 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */
$s4 = "\\System32\\cmd.ex\\System32\\rundllP" fullword ascii
$s5 = "Z:\\D\\GIT\\anchorDns.llvm\\Bin\\x64\\Release\\anchorDNS_x64.pdb" fullword ascii
$s6 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s7 = "cutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><appli" ascii
$s8 = "thExecute" fullword ascii
$s9 = "on xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSe" ascii
$s10 = "WinHTTP loader/1.0" fullword wide
$s11 = "AppPolicyGetThreadInitializationType" fullword ascii
$s12 = "AnchorDNS.cpp" fullword ascii
$s13 = "hardWorker.cpp" fullword ascii
$s14 = "operator<=>" fullword ascii
$s15 = "operator co_await" fullword ascii
$s16 = "/C PowerShell \"Start-Slemove-Iteep 3; Re" fullword wide
$s17 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo><security><requestedPrivileges><requeste" ascii
$s18 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
$s19 = "UAWAVAUATVWSH" fullword ascii
$s20 = "AWAVAUATVWUSH" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 1000KB and
( pe.imphash() == "e2450fb3cc5b1b7305e3193fe03f3369" and ( 1 of ($x*) or all of them ) )
}

rule anchorAsjuster_x64 {
meta:
description = "files - file anchorAsjuster_x64.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-02-22"
hash1 = "3ab8a1ee10bd1b720e1c8a8795e78cdc09fec73a6bb91526c0ccd2dc2cfbc28d"
strings:
$s1 = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii
$s2 = "anchorAdjuster* --source=<source file> --target=<target file> --domain=<domain name> --period=<recurrence interval, minutes, def" ascii
$s3 = "anchorAdjuster* --source=<source file> --target=<target file> --domain=<domain name> --period=<recurrence interval, minutes, def" ascii
$s4 = "target file \"%s\"" fullword ascii
$s5 = "--target=" fullword ascii
$s6 = "hemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii
$s7 = "error write file, written %i bytes, need write %i bytes, error code %i" fullword ascii
$s8 = "error create file \"%s\", code %i" fullword ascii
$s9 = "guid: %s, shift 0x%08X(%i)" fullword ascii
$s10 = "ault value 15> -guid --count=<count of instances>" fullword ascii
$s11 = "domain: shift 0x%08X(%i)" fullword ascii
$s12 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii
$s13 = "vileges></security></trustInfo><application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http:/" ascii
$s14 = "wrong protocol type" fullword ascii /* Goodware String - occured 567 times */
$s15 = "network reset" fullword ascii /* Goodware String - occured 567 times */
$s16 = "owner dead" fullword ascii /* Goodware String - occured 567 times */
$s17 = "connection already in progress" fullword ascii /* Goodware String - occured 567 times */
$s18 = "network down" fullword ascii /* Goodware String - occured 567 times */
$s19 = "protocol not supported" fullword ascii /* Goodware String - occured 568 times */
$s20 = "connection aborted" fullword ascii /* Goodware String - occured 568 times */
condition:
uint16(0) == 0x5a4d and filesize < 700KB and
( pe.imphash() == "9859b7a32d1227be2ca925c81ae9265e" and all of them )
}
