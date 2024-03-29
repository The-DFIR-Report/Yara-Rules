/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-03-29
Identifier: Case 1051 Sodinokibi (aka REvil) Ransomware
Reference: https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule Sodinokibi_032021 {
meta:
description = "files - file DomainName.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-03-21"
hash1 = "2896b38ec3f5f196a9d127dbda3f44c7c29c844f53ae5f209229d56fd6f2a59c"
strings:
$s1 = "vmcompute.exe" fullword wide
$s2 = "vmwp.exe" fullword wide
$s3 = "bootcfg /raw /a /safeboot:network /id 1" fullword ascii
$s4 = "bcdedit /set {current} safeboot network" fullword ascii
$s5 = "7+a@P>:N:0!F$%I-6MBEFb M" fullword ascii
$s6 = "jg:\"\\0=Z" fullword ascii
$s7 = "ERR0R D0UBLE RUN!" fullword wide
$s8 = "VVVVVPQ" fullword ascii
$s9 = "VVVVVWQ" fullword ascii
$s10 = "Running" fullword wide /* Goodware String - occured 159 times */
$s11 = "expand 32-byte kexpand 16-byte k" fullword ascii
$s12 = "9RFIT\"&" fullword ascii
$s13 = "jZXVf9F" fullword ascii
$s14 = "tCWWWhS=@" fullword ascii
$s15 = "vmms.exe" fullword wide /* Goodware String - occured 1 times */
$s16 = "JJwK9Zl" fullword ascii
$s17 = "KkT37uf4nNh2PqUDwZqxcHUMVV3yBwSHO#K" fullword ascii
$s18 = "0*090}0" fullword ascii /* Goodware String - occured 1 times */
$s19 = "5)5I5a5" fullword ascii /* Goodware String - occured 1 times */
$s20 = "7-7H7c7" fullword ascii /* Goodware String - occured 1 times */
condition:
uint16(0) == 0x5a4d and filesize < 400KB and
( pe.imphash() == "031931d2f2d921a9d906454d42f21be0" or 8 of them )
}

rule icedid_032021_1 {
meta:
description = "files - file skull-x64.dat"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-03-21"
hash1 = "59a2a5fae1c51afbbf1bf8c6eb0a65cb2b8575794e3890f499f8935035e633fc"
strings:
$s1 = "update" fullword ascii /* Goodware String - occured 207 times */
$s2 = "PstmStr" fullword ascii
$s3 = "mRsx0k/" fullword wide
$s4 = "D$0lzK" fullword ascii
$s5 = "A;Zts}H" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 100KB and
( pe.imphash() == "67a065c05a359d287f1fed9e91f823d5" and ( pe.exports("PstmStr") and pe.exports("update") ) or all of them )
}

rule icedid_032021_2 {
meta:
description = "1 - file license.dat"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-03-21"
hash1 = "45b6349ee9d53278f350b59d4a2a28890bbe9f9de6565453db4c085bb5875865"
strings:
$s1 = "+ M:{`n-" fullword ascii
$s2 = "kwzzdd" fullword ascii
$s3 = "w5O- >z" fullword ascii
$s4 = "RRlK8n@~" fullword ascii
$s5 = "aQXDUkBC" fullword ascii
$s6 = "}i.ZSj*" fullword ascii
$s7 = "kLeSM?" fullword ascii
$s8 = "qmnIqD\")P" fullword ascii
$s9 = "aFAeU!," fullword ascii
$s10 = "Qjrf\"Q" fullword ascii
$s11 = "PTpc,!P#" fullword ascii
$s12 = "r@|JZOkfmT2" fullword ascii
$s13 = "aPvBO,4" fullword ascii
$s14 = ">fdFhl^S8Z" fullword ascii
$s15 = "[syBE0\\" fullword ascii
$s16 = "`YFOr.JH" fullword ascii
$s17 = "C6ZVVF j7}" fullword ascii
$s18 = "LPlagce" fullword ascii
$s19 = "NLeF_-e`" fullword ascii
$s20 = "HRRF|}O" fullword ascii
condition:
uint16(0) == 0x43da and filesize < 1000KB and
8 of them
}
