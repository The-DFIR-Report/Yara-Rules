/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-04-27
Identifier: Case 3521 Trickbot Brief: Creds and Beacons
Reference: https://thedfirreport.com/2021/05/02/trickbot-brief-creds-and-beacons/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule click_php {
meta:
description = "files - file click.php.dll"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-04-27"
hash1 = "0ae86e5abbc09e96f8c1155556ca6598c22aebd73acbba8d59f2ce702d3115f8"
strings:
$s1 = "f_+ (Q" fullword wide
$s2 = "'/l~;2m" fullword wide
$s3 = "y'L])[" fullword wide
$s4 = "1!1I1m1s1" fullword ascii
$s5 = "&+B\"wm" fullword wide
$s6 = ">jWR=C" fullword wide
$s7 = "W!\\R.S" fullword wide
$s8 = "r-`4?b6" fullword wide
$s9 = "]Iip!x" fullword wide
$s10 = "!k{l`<" fullword wide
$s11 = "D~C:RA" fullword wide
$s12 = "]{T~as" fullword wide
$s13 = "7%8+8^8" fullword ascii
$s14 = "f]-hKa" fullword wide
$s15 = "StartW" fullword ascii /* Goodware String - occured 5 times */
condition:
uint16(0) == 0x5a4d and filesize < 1000KB and
( pe.imphash() == "8948fb754b7c37bc4119606e044f204c" and pe.exports("StartW") or 10 of them )
}
