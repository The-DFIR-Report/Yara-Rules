/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-06-03
Identifier: Case 3580 WebLogic RCE Leads to XMRig
Reference: https://thedfirreport.com/2021/06/03/weblogic-rce-leads-to-xmrig/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule sysrv013 {
meta:
description = "files - file sysrv013.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-06-03"
hash1 = "80bc76202b75201c740793ea9cd33b31cc262ef01738b053e335ee5d07a5ba96"
strings:
$s1 = "eDumped" fullword ascii
$s2 = "OGhZVFNVRms6" fullword ascii /* base64 encoded string '8hYTSUFk:' */
$s3 = "sdumpsebslemW^" fullword ascii
$s4 = ":ERNEL32.DLLODe?" fullword ascii
$s5 = "pircsek" fullword ascii
$s6 = "IDE5NC4xNDUu" fullword ascii /* base64 encoded string ' 194.145.' */
$s7 = "333444" ascii /* reversed goodware string '444333' */
$s8 = "aHx8d2dldCAtLXVzZXItYW" fullword ascii /* base64 encoded string 'h||wget --user-a' */
$s9 = "h -c {%" fullword ascii
$s10 = "?$?)?2?9?{" fullword ascii /* hex encoded string ')' */
$s11 = ";5A;6D2!D" fullword ascii /* hex encoded string 'Zm-' */
$s12 = "3GRAt\\5" fullword ascii
$s13 = "Gorget{" fullword ascii
$s14 = "7!7&7,727" fullword ascii /* hex encoded string 'ww'' */
$s15 = "* {5C;" fullword ascii
$s16 = "fsftp_fC" fullword ascii
$s17 = "POSTulL" fullword ascii
$s18 = "gogetv/" fullword ascii
$s19 = "\\x86+.pdb" fullword ascii
$s20 = "_DIRCWD?" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 10000KB and
( pe.imphash() == "406f4cbdf82bde91761650ca44a3831a" or 8 of them )
}
