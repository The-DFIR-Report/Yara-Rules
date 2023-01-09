/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2023-01-08
   Identifier: Case 17386 Gozi
   Reference: https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts
*/

/* Rule Set ----------------------------------------------------------------- */

rule gozi_17386_6570872_lnk
{
	meta:
		description = "Gozi - file 6570872.lnk"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts"
		date = "2023-01-08"
		hash1 = "c6b605a120e0d3f3cbd146bdbc358834"
	strings:
		$s1 = "..\\..\\..\\..\\me\\alsoOne.bat" fullword wide
		$s2 = "alsoOne.bat" fullword wide
		$s3 = "c:\\windows\\explorer.exe" fullword wide
		$s4 = "%SystemRoot%\\explorer.exe" fullword wide
	condition:
		uint16(0) == 0x004c and
		filesize < 4KB and
		all of them
}

rule gozi_17386_adcomp_bat
{
	meta:
		description = "Gozi - file adcomp.bat"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts"
		date = "2023-01-08"
		hash1 = "eb2335e887875619b24b9c48396d4d48"
	strings:
		$s1 = "powershell" fullword
		$s2 = ">> log2.txt" fullword
		$s3 = "Get-ADComputer" fullword
	condition:
		$s1 at 0 and
		filesize < 500 and
		all of them
}

rule gozi_17386_alsoOne_bat
{
	meta:
		description = "Gozi - file alsoOne.bat"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts"
		date = "2023-01-08"
		hash1 = "c03f5e2bc4f2307f6ee68675d2026c82"
	strings:
		$s1 = "set %params%=hello" fullword
		$s2 = "me\\canWell.js hello" fullword
		$s3 = "cexe lldnur" fullword
		$s4 = "revreSretsigeRllD" fullword
	condition:
		$s1 at 0 and
		filesize < 500 and
		all of them
}

rule gozi_17386_canWell_js
{
	meta:
		description = "Gozi - file canWell.js"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts"
		date = "2023-01-08"
		hash1 = "6bb867e53c46aa55a3ae92e425c6df91"
	strings:
		//00000000  2F 2A 2A 0D 0A 09 57 68  6E 6C 64 47 68 0D 0A 2A  /**...WhnldGh..*
		//00000010  2F                                               /
		$h1 = { 2F 2A 2A 0D 0A 09 57 68 6E 6C 64 47 68 0D 0A 2A 2F }
		$s1 = "reverseString" fullword
		$s2 = "123.com" fullword
		$s3 = "itsIt.db" fullword
		$s4 = "function ar(id)" fullword
		$s5 = "WScript.CreateObject" fullword
	condition:
		$h1 at 0 and
		filesize < 1KB and
		all of ($s*)
}

rule gozi_17386_itsIt_db
{
	meta:
		description = "Gozi - file itsIt.db"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts"
		date = "2023-01-08"
		hash1 = "60375d64a9a496e220b6eb1b63e899b3"
	strings:
		$s1 = "EoJA1.dll" fullword
		$s2 = "AXMsDQbUbhdpHgumy" fullword
		$s3 = "DllRegisterServer" fullword
		$s4 = "DqvdfVJXumSGuxDbQeifDE" fullword
		$s5 = "GsvFugemhLmFRebByHWZLIlt" fullword
		$s6 = "IBDFzyzaYYbvLCdANNWobWzkHefitgP" fullword
		$s7 = "KWwSSdVAwGpuPZJemC" fullword
		$s8 = "LRZeayHLHiLXcxFjinEZmyaMXWpoF" fullword
		$s9 = "LcVopTSimzPyMznceIIepGGLs" fullword
		$s10 = "OkJXHEIxVkZenNREJnYdhtufvRv" fullword
		$s11 = "OtsltXyqwGKmKSYm" fullword
		$s12 = "OvzfwfDhXuXhLmzEvnwCNPcfYAodAip" fullword
		$s13 = "QQASfqqFsaIyuodrOEzmiYhXFBhK" fullword
		$s14 = "RNsFxmZdRyUXEpddwSgBPDKQPQW" fullword
		$s15 = "RxfeQKNVUecCmdLsHQAGMbqVDxDAR" fullword
		$s16 = "SKRXxPrnvmLVjzGDJ" fullword
		$s17 = "UOGamDxqKzMifBHNcnBjIecgOy" fullword
		$s18 = "VHPqYBENjtlIcAUDdVEHyQrPsRjrWb" fullword
		$s19 = "VHYmMulTaXxJkuTCbDpFOCoWjdFipiT" fullword
		$s20 = "WJkBmOWdIlTJWBXfKCLRluK" fullword
		$s21 = "YIskifvVtpCHTPVefoogyKpjNpKk" fullword
		$s22 = "YqnsziMxolCUEpCyF" fullword
		$s23 = "aHjfpBCMGTOHtAxeJeqvYJiJipIc" fullword
		$s24 = "btmXEDkzSVQrIekKBbgAyAjFzB" fullword
		$s25 = "iZwERsKOdaNkDjJUj" fullword
		$s26 = "ifNYULjNknlPOsikeeFKq" fullword
		$s27 = "jZTjetqmFfnLpMHfBmKFXSWNjK" fullword
		$s28 = "kxNmMsXFaSQwVCttBDpieAV" fullword
		$s29 = "phDeNsVAkciNIDphsSICKbhrF" fullword
		$s30 = "srJhGTXYGHCFyCLmlYgSpAB" fullword
		$s31 = "tvMVzGtbiBFVgcrXhUsAKAuKQXi" fullword
		$s32 = "vowTIpYzkeDnPYtsuRYfGIGg" fullword
		$s33 = "GCTL" fullword
	condition:
		uint16(0) == 0x5a4d and
		filesize < 500KB and
		all of them
}
