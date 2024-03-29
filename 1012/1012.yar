/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-01-10
Identifier: Case 1012 Trickbot Still Alive and Well
Reference: https://thedfirreport.com/2021/01/11/trickbot-still-alive-and-well/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule cobalt_strike_TSE588C {
meta:
description = "exe - file TSE588C.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-01-05"
hash1 = "32c13df5d411bf5a114e2021bbe9ffa5062ed1db91075a55fe4182b3728d62fe"
strings:
$s1 = "mneploho86.dll" fullword ascii
$s2 = "C:\\projects\\Project1\\Project1.pdb" fullword ascii
$s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s4 = "AppPolicyGetThreadInitializationType" fullword ascii
$s5 = "boltostrashno.nfo" fullword ascii
$s6 = "operator<=>" fullword ascii
$s7 = "operator co_await" fullword ascii
$s8 = "?7; ?<= <?= 6<" fullword ascii /* hex encoded string 'v' */
$s9 = ".data$rs" fullword ascii
$s10 = "tutoyola" fullword ascii
$s11 = "Ommk~z#K`majg`i4.itg~\".jkhbozk" fullword ascii
$s12 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
$s13 = "OVOVPWTOVOWOTF" fullword ascii
$s14 = "vector too long" fullword ascii
$s15 = "n>log2" fullword ascii
$s16 = "\\khk|k|4.fzz~4!!majk d" fullword ascii
$s17 = "network reset" fullword ascii /* Goodware String - occured 567 times */
$s18 = "wrong protocol type" fullword ascii /* Goodware String - occured 567 times */
$s19 = "owner dead" fullword ascii /* Goodware String - occured 567 times */
$s20 = "connection already in progress" fullword ascii /* Goodware String - occured 567 times */
condition:
uint16(0) == 0x5a4d and filesize < 900KB and
( pe.imphash() == "bb8169128c5096ea026d19888c139f1a" or 10 of them )
}

rule trickbot_kpsiwn {
meta:
description = "exe - file kpsiwn.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-01-05"
hash1 = "e410123bde6a317cadcaf1fa3502301b7aad6f528d59b6b60c97be077ef5da00"
strings:
$s1 = "C:\\Windows\\explorer.exe" fullword ascii
$s2 = "constructor or from DllMain." fullword ascii
$s3 = "esource" fullword ascii
$s4 = "Snapping window demonstration" fullword wide
$s5 = "EEEEEEEEEFFB" ascii
$s6 = "EEEEEEEEEEFC" ascii
$s7 = "EEEEEEEEEEFD" ascii
$s8 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" fullword ascii
$s9 = "EFEEEEEEEEEB" ascii
$s10 = "e[!0LoG" fullword ascii
$s11 = ">*P<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">" fullword ascii
$s12 = "o};k- " fullword ascii
$s13 = "YYh V+ i" fullword ascii
$s14 = "fdlvic" fullword ascii
$s15 = "%FD%={" fullword ascii
$s16 = "QnzwM#`8" fullword ascii
$s17 = "xfbS/&s:" fullword ascii
$s18 = "1#jOSV9\"" fullword ascii
$s19 = "JxYt1L=]" fullword ascii
$s20 = "a3NdcMFSZEmJwXod1oyI@Tj4^mY+UsZqK3>fTg<P*$4DC?y@esDpRk@T%t" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 1000KB and
( pe.imphash() == "a885f66621e03089e6c6a82d44a5ebe3" or 10 of them )
}

rule cobalt_strike_TSE28DF {
meta:
description = "exe - file TSE28DF.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-01-05"
hash1 = "65282e01d57bbc75f24629be9de126f2033957bd8fe2f16ca2a12d9b30220b47"
strings:
$s1 = "mneploho86.dll" fullword ascii
$s2 = "C:\\projects\\Project1\\Project1.pdb" fullword ascii
$s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s4 = "AppPolicyGetThreadInitializationType" fullword ascii
$s5 = "boltostrashno.nfo" fullword ascii
$s6 = "operator<=>" fullword ascii
$s7 = "operator co_await" fullword ascii
$s8 = ".data$rs" fullword ascii
$s9 = "tutoyola" fullword ascii
$s10 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
$s11 = "vector too long" fullword ascii
$s12 = "wrong protocol type" fullword ascii /* Goodware String - occured 567 times */
$s13 = "network reset" fullword ascii /* Goodware String - occured 567 times */
$s14 = "owner dead" fullword ascii /* Goodware String - occured 567 times */
$s15 = "connection already in progress" fullword ascii /* Goodware String - occured 567 times */
$s16 = "network down" fullword ascii /* Goodware String - occured 567 times */
$s17 = "protocol not supported" fullword ascii /* Goodware String - occured 568 times */
$s18 = "connection aborted" fullword ascii /* Goodware String - occured 568 times */
$s19 = "network unreachable" fullword ascii /* Goodware String - occured 569 times */
$s20 = "host unreachable" fullword ascii /* Goodware String - occured 571 times */
condition:
uint16(0) == 0x5a4d and filesize < 700KB and
( pe.imphash() == "ab74ed3f154e02cfafb900acffdabf9e" or all of them )
}
