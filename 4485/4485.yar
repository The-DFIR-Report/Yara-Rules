/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-07-13
Identifier: Case 4485 IcedID and Cobalt Strike vs Antivirus
Reference: https://thedfirreport.com/2021/07/19/icedid-and-cobalt-strike-vs-antivirus/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule textboxNameNamespace {
meta:
description = "4485 - file textboxNameNamespace.hta"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-07-13"
hash1 = "b17c7316f5972fff42085f7313f19ce1c69b17bf61c107b1ccf94549d495fa42"
strings:
$s1 = "idGNlamJvbWV0c3lzZWxpZi5nbml0cGlyY3MiKHRjZWpiT1hldml0Y0Egd2VuID0gTG1lciByYXY7KSJsbGVocy50cGlyY3N3Iih0Y2VqYk9YZXZpdGNBIHdlbiA9IGV" ascii /* base64 encoded string 'tcejbometsyselif.gnitpircs"(tcejbOXevitcA wen = Lmer rav;)"llehs.tpircsw"(tcejbOXevitcA wen = e' */
$s2 = "/<html><body><div id='variantDel'>fX17KWUoaGN0YWN9O2Vzb2xjLnRzbm9Dbm90dHVCd2VpdjspMiAsImdwai5lY2Fwc2VtYU5lbWFOeG9idHhldFxcY2lsYn" ascii
$s3 = "oveTo(-100, -100);var swapLength = tplNext.getElementById('variantDel').innerHTML.split(\"aGVsbG8\");var textSinLibrary = ptrSin" ascii
$s4 = "wxyz0123456789+/</div><script language='javascript'>function varMainInt(tmpRepo){return(new ActiveXObject(tmpRepo));}function bt" ascii
$s5 = "VwXFxzcmVzdVxcOmMiKGVsaWZvdGV2YXMudHNub0Nub3R0dUJ3ZWl2Oyl5ZG9iZXNub3BzZXIuZXRhREl4b2J0eGV0KGV0aXJ3LnRzbm9Dbm90dHVCd2VpdjsxID0gZX" ascii
$s6 = "ript><script language='vbscript'>Function byteNamespaceReference(variantDel) : Set WLength = CreateObject(queryBoolSize) : With " ascii
$s7 = "WLength : .language = \"jscript\" : .timeout = 60000 : .eval(variantDel) : End With : End Function</script><script language='vbs" ascii
$s8 = "FkZGEvbW9jLmIwMjAyZ25pcm9ieXRyZXZvcC8vOnB0dGgiICwiVEVHIihuZXBvLmV0YURJeG9idHhldDspInB0dGhsbXguMmxteHNtIih0Y2VqYk9YZXZpdGNBIHdlbi" ascii
$s9 = "pJMTZBb0hjcXBYbVI1ZUI0YXF0SVhWWlZkRkhvZjFEZy9qYWVMTGlmc3doOW9EaEl2QlllYnV1dWxPdktuQWFPYm43WGNieFdqejQ1V3dTOC8xMzIxNi9PUnFEb01aL2" ascii
$s10 = "B5dC50c25vQ25vdHR1QndlaXY7bmVwby50c25vQ25vdHR1QndlaXY7KSJtYWVydHMuYmRvZGEiKHRjZWpiT1hldml0Y0Egd2VuID0gdHNub0Nub3R0dUJ3ZWl2IHJhdn" ascii
$s11 = "t><script language='javascript'>libView['close']();</script></body></html>" fullword ascii
$s12 = "t5cnR7KTAwMiA9PSBzdXRhdHMuZXRhREl4b2J0eGV0KGZpOykoZG5lcy5ldGFESXhvYnR4ZXQ7KWVzbGFmICwiNE9Uc3NldUk9ZmVyPzZnb2QvNzcwODMvUG10RkQzeE" ascii
$s13 = "tYU5vcmV6IHJhdg==aGVsbG8msscriptcontrol.scriptcontrol</div><div id='exLeftLink'>ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv" ascii
$s14 = "nGlob(pasteVariable){return(tplNext.getElementById(pasteVariable).innerHTML);}function lConvert(){return(btnGlob('exLeftLink'));" ascii
$s15 = "ipt'>Call byteNamespaceReference(textSinLibrary)</script><script language='vbscript'>Call byteNamespaceReference(remData)</scrip" ascii
$s16 = "Ex](x)];b=(b<<6)+c;l+=6;while(l>=8){((a=(b>>>(l-=8))&0xff)||(x<(L-2)))&&(vbaBD+=w(a));}}return(vbaBD);};function ptrSingleOpt(be" ascii
$s17 = "eOpt(bytesGeneric(swapLength[0]));var remData = ptrSingleOpt(bytesGeneric(swapLength[1]));var queryBoolSize = swapLength[2];</sc" ascii
$s18 = "}function bytesGeneric(s){var e={}; var i; var b=0; var c; var x; var l=0; var a; var vbaBD=''; var w=String.fromCharCode; var L" ascii
$s19 = "=s.length;var counterEx = ptrSingleOpt('tArahc');for(i=0;i<64;i++){e[lConvert()[counterEx](i)]=i;}for(x=0;x<L;x++){c=e[s[counter" ascii
$s20 = "foreRight){return beforeRight.split('').reverse().join('');}libView = window;tplNext = document;libView.resizeTo(1, 1);libView.m" ascii
condition:
uint16(0) == 0x3c2f and filesize < 7KB and
8 of them
}

rule case_4485_adf {
meta:
description = "files - file adf.bat"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-07-13"
hash1 = "f6a377ba145a5503b5eb942d17645502eddf3a619d26a7b60df80a345917aaa2"
strings:
$x1 = "adfind.exe"
$s2 = "objectcategory=person" fullword ascii
$s3 = "objectcategory=computer" fullword ascii
$s4 = "adfind.exe -gcb -sc trustdmp > trustdmp.txt" fullword ascii
$s5 = "adfind.exe -sc trustdmp > trustdmp.txt" fullword ascii
$s6 = "adfind.exe -subnets -f (objectCategory=subnet)> subnets.txt" fullword ascii
$s7 = "(objectcategory=group)" fullword ascii
$s8 = "(objectcategory=organizationalUnit)" fullword ascii
condition:
uint16(0) == 0x6463 and filesize < 1KB and ( 1 of ($x*) and 6 of ($s*))
}

rule case_4485_Muif {
meta:
description = "4485 - file Muif.dll"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-07-13"
hash1 = "8b9d605b826258e07e63687d1cefb078008e1a9c48c34bc131d7781b142c84ab"
strings:
$s1 = "Common causes completion include incomplete download and damaged media" fullword ascii
$s2 = "An error occurred writing to the file" fullword ascii
$s3 = "asks should be performed?" fullword ascii
$s4 = "The waiting time for the end of the launch was exceeded for an unknown reason" fullword ascii
$s5 = "Select the Start Menu folder in which you would like Setup to create the programs shortcuts, then click Next. Which additional t" ascii
$s6 = "HcA<E3" fullword ascii /* Goodware String - occured 1 times */
$s7 = "D$(9D$@u" fullword ascii /* Goodware String - occured 1 times */
$s8 = "Select the Start Menu folder in which you would like Setup to create the programs shortcuts, then click Next. Which additional t" ascii
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

rule textboxNameNamespace_2 {
meta:
description = "4485 - file textboxNameNamespace.jpg"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-07-13"
hash1 = "010f52eda70eb9ff453e3af6f3d9d20cbda0c4075feb49c209ca1c250c676775"
strings:
$s1 = "uwunhkqlzle.dll" fullword ascii
$s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s3 = "operator co_await" fullword ascii
$s4 = "ggeaxcx" fullword ascii
$s5 = "wttfzwz" fullword ascii
$s6 = "fefewzydtdu" fullword ascii
$s7 = "ilaeemjyjwzjwj" fullword ascii
$s8 = "enhzmqryc" fullword ascii
$s9 = "flchfonfpzcwyrg" fullword ascii
$s10 = "dayhcsokc" fullword ascii
$s11 = "mtqnlfpbxghmlupsn" fullword ascii
$s12 = "zqeoctx" fullword ascii
$s13 = "ryntfydpykrdcftxx" fullword ascii
$s14 = "atxvtwd" fullword ascii
$s15 = "icjshmfrldy" fullword ascii
$s16 = "lenkuktrncmxiafgl" fullword ascii
$s17 = "alshaswlqmhptxpc" fullword ascii
$s18 = "izonphi" fullword ascii
$s19 = "atttyokowqnj" fullword ascii
$s20 = "nwvohpazb" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 500KB and
( pe.imphash() == "4d46e641e0220fb18198a7e15fa6f49f" and ( pe.exports("PluginInit") and pe.exports("alshaswlqmhptxpc") and pe.exports("amgqilvxdufvpdbwb") and pe.exports("atttyokowqnj") and pe.exports("atxvtwd") and pe.exports("ayawgsgkusfjmq") ) or 8 of them )
}

rule case_4485_ekix4 {
meta:
description = "4485 - file ekix4.dll"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-07-13"
hash1 = "e27b71bd1ba7e1f166c2553f7f6dba1d6e25fa2f3bb4d08d156073d49cbc360a"
strings:
$s1 = "f159.dll" fullword ascii
$s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s3 = "ossl_store_get0_loader_int" fullword ascii
$s4 = "loader incomplete" fullword ascii
$s5 = "log conf missing description" fullword ascii
$s6 = "SqlExec" fullword ascii
$s7 = "process_include" fullword ascii
$s8 = "EVP_PKEY_get0_siphash" fullword ascii
$s9 = "process_pci_value" fullword ascii
$s10 = "EVP_PKEY_get_raw_public_key" fullword ascii
$s11 = "EVP_PKEY_get_raw_private_key" fullword ascii
$s12 = "OSSL_STORE_INFO_get1_NAME_description" fullword ascii
$s13 = "divisor->top > 0 && divisor->d[divisor->top - 1] != 0" fullword wide
$s14 = "ladder post failure" fullword ascii
$s15 = "operation fail" fullword ascii
$s16 = "ssl command section not found" fullword ascii
$s17 = "log key invalid" fullword ascii
$s18 = "cms_get0_econtent_type" fullword ascii
$s19 = "log conf missing key" fullword ascii
$s20 = "ssl command section empty" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 11000KB and
( pe.imphash() == "547a74a834f9965f00df1bd9ed30b8e5" or 8 of them )
}
