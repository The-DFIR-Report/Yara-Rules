/*
YARA Rule Set
Author: The DFIR Report
Date: 2022-09-12
Identifier: Emotet Case 14335
Reference: https://thedfirreport.com/2022/09/12/dead-or-alive-an-emotet-story/
*/
/* Rule Set ----------------------------------------------------------------- */


import "pe"


rule llJyMIOvft_14335 {
   meta:
      description = "llJyMIOvft.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2022/09/12/dead-or-alive-an-emotet-story/"
      date = "2022-09-12"
      hash1 = "2b2e00ed89ce6898b9e58168488e72869f8e09f98fecb052143e15e98e5da9df"
   strings:
      $s1 = "Project1.dll" fullword ascii
      $s2 = "!>v:\"6;" fullword ascii
      $s3 = "y6./XoFz_6fw%r:6*" fullword ascii
      $s4 = "u3!RuF%OR_O*^$nw7&<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">" fullword ascii
      $s5 = "*/B+ n" fullword ascii
      $s6 = "ZnwFY66" fullword ascii
      $s7 = "1!f%G%w" fullword ascii
      $s8 = "QKMaXCL6" fullword ascii
      $s9 = "IMaRlh9" fullword ascii
      $s10 = "_BZRDe'7&7<<!{nBLU" fullword ascii
      $s11 = "lw7\"668!qZNL_EIS7IiMa" fullword ascii
      $s12 = "IS6\\JMtdHh0Piw2/PuH" fullword ascii
      $s13 = "iw#!RuF%OR__*^$nw76668!qZNL_EYS7I" fullword ascii
      $s14 = ".RuF%LR__*^$" fullword ascii
      $s15 = "^<_EHJ3IPLPeZX0Phg7!BAK%_" fullword ascii
      $s16 = "ilG8Rn\"2OIkY*E%zw'v669(pZGn_EH_6IE" fullword ascii
      $s17 = "ilg7Rnr0OI^]*JTnw6\"76<" fullword ascii
      $s18 = "Broken pipe" fullword ascii /* Goodware String - occured 742 times */
      $s19 = "Permission denied" fullword ascii /* Goodware String - occured 823 times */
      $s20 = "v)(Ro\">OHkU*D%xw9" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      ( pe.imphash() == "066c972d2129d0e167d371a0abfcf03b" and ( pe.exports("YAeJyEAYL7F4eDck6YUaf") and pe.exports("fmFkmnQYB5TC2Sq5NGFkK") and pe.exports("nrDjhnkd9nedaQwcCY") ) or 12 of them )
}


rule UOmCgbXygCe_14335 {
   meta:
      description = "UOmCgbXygCe.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2022/09/12/dead-or-alive-an-emotet-story/"
      date = "2022-09-12"
      hash1 = "f4c085ef1ba7e78a17a9185e4d5e06163fe0e39b6b0dc3088b4c1ed11c0d726b"
   strings:
      $s1 = "runsuite.log" fullword ascii
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s3 = "f73.exe" fullword ascii
      $s4 = "Processing test line %ld %s leaked %d" fullword ascii
      $s5 = "Internal error: xmlSchemaTypeFixup, complex type '%s': the <simpleContent><restriction> is missing a <simpleType> child, but was" ascii
      $s6 = "The target namespace of the included/redefined schema '%s' has to be absent or the same as the including/redefining schema's tar" ascii
      $s7 = "The target namespace of the included/redefined schema '%s' has to be absent, since the including/redefining schema has no target" ascii
      $s8 = "A <simpleType> is expected among the children of <restriction>, if <simpleContent> is used and the base type '%s' is a complex t" ascii
      $s9 = "there is at least one entity reference in the node-tree currently being validated. Processing of entities with this XML Schema p" ascii
      $s10 = "## %s test suite for Schemas version %s" fullword ascii
      $s11 = "Internal error: %s, " fullword ascii
      $s12 = "If <simpleContent> and <restriction> is used, the base type must be a simple type or a complex type with mixed content and parti" ascii
      $s13 = "For a string to be a valid default, the type definition must be a simple type or a complex type with simple content or mixed con" ascii
      $s14 = "For a string to be a valid default, the type definition must be a simple type or a complex type with mixed content and a particl" ascii
      $s15 = "Could not open the log file, running in verbose mode" fullword ascii
      $s16 = "not validating will not read content for PE entity %s" fullword ascii
      $s17 = "Skipping import of schema located at '%s' for the namespace '%s', since this namespace was already imported with the schema loca" ascii
      $s18 = "(annotation?, (simpleContent | complexContent | ((group | all | choice | sequence)?, ((attribute | attributeGroup)*, anyAttribut" ascii
      $s19 = "get namespace" fullword ascii
      $s20 = "instance %s fails to parse" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      ( pe.imphash() == "bcf185f1308ffd9e4249849d206d9d0c" and pe.exports("xmlEscapeFormatString") or 12 of them )
}


rule info_1805_14335 {
   meta:
      description = "info_1805.xls"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2022/09/12/dead-or-alive-an-emotet-story/"
      date = "2022-09-12"
      hash1 = "e598b9700e13f2cb1c30c6d9230152ed5716a6d6e25db702576fefeb6638005e"
   strings:
      $s1 = "32.exe" fullword ascii
      $s2 = "System32\\X" fullword ascii
      $s3 = "DocumentOwnerPassword" fullword wide
      $s4 = "DocumentUserPassword" fullword wide
      $s5 = "t\"&\"t\"&\"p\"&\"s:\"&\"//lo\"&\"pe\"&\"sp\"&\"ub\"&\"li\"&\"ci\"&\"da\"&\"de.c\"&\"o\"&\"m/cgi-bin/e\"&\"5R\"&\"5o\"&\"G4\"&\"" ascii
      $s6 = "UniresDLL" fullword ascii
      $s7 = "OEOGAJPGJPAG" fullword ascii
      $s8 = "\\Windows\\" fullword ascii
      $s9 = "_-* #,##0.00_-;\\-* #,##0.00_-;_-* \"-\"??_-;_-@_-" fullword ascii
      $s10 = "_-* #,##0_-;\\-* #,##0_-;_-* \"-\"_-;_-@_-" fullword ascii
      $s11 = "_-;_-* \"" fullword ascii
      $s12 = "^{)P -z)" fullword ascii
      $s13 = "ResOption1" fullword ascii
      $s14 = "DocumentSummaryInformation" fullword wide /* Goodware String - occured 41 times */
      $s15 = "Root Entry" fullword wide /* Goodware String - occured 46 times */
      $s16 = "SummaryInformation" fullword wide /* Goodware String - occured 50 times */
      $s17 = "A\",\"JJCCBB\"" fullword ascii
      $s18 = "Excel 4.0" fullword ascii
      $s19 = "Microsoft Print to PDF" fullword wide
      $s20 = "\"_-;\\-* #,##0.00\\ \"" fullword wide /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0xcfd0 and filesize < 200KB and
      all of them
}


rule cobalt_strike_14435_dll_1 {
   meta:
      description = "1.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-09-12"
      hash1 = "1b9c9e4ed6dab822b36e3716b1e8f046e92546554dff9bdbd18c822e18ab226b"
   strings:
      $s1 = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii
      $s2 = "CDNS Project.dll" fullword ascii
      $s3 = "hemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii
      $s4 = "Hostname to lookup:" fullword wide
      $s5 = "Hostnames:" fullword wide
      $s6 = "wOshV- D3\"RIcP@DN \\" fullword ascii
      $s7 = "T4jk{zrvG#@KRO* d'z" fullword ascii
      $s8 = "CDNS Project Version 1.0" fullword wide
      $s9 = "zK$%S.cPO>rtW" fullword ascii
      $s10 = "vOsh.HSDiXRI" fullword ascii
      $s11 = "l4p.oZewOsh7zP" fullword ascii
      $s12 = "5p2o.ewOsh7H" fullword ascii
      $s13 = "h7H.DiX" fullword ascii
      $s14 = "l4pWo.ewOsh[H%DiXRI" fullword ascii
      $s15 = "rEWS).lpp~o" fullword ascii
      $s16 = ",m}_lOG" fullword ascii
      $s17 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii
      $s18 = "vileges></security></trustInfo><application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http:/" ascii
      $s19 = "tn9- 2" fullword ascii
      $s20 = "PDiXRI7" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      ( pe.imphash() == "d1aef4e37a548a43a95d44bd2f8c0afc" or 8 of them )
}


rule cobalt_strike_14435_dll_2 {
   meta:
      description = "32.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2022/09/12/dead-or-alive-an-emotet-story/"
      date = "2022-09-12"
      hash1 = "76bfb4a73dc0d3f382d3877a83ce62b50828f713744659bb21c30569d368caf8"
   strings:
      $x1 = "mail glide drooping dismiss collation production mm refresh murderer start parade subscription accident retorted carter stalls r" ascii
      $s2 = "vlu405yd87.dll" fullword ascii
      $s3 = "XYVZSWWVU" fullword ascii /* base64 encoded string 'aVRYeT' */
      $s4 = "ZYWVWSXVT" fullword ascii /* base64 encoded string 'aeVIuS' */
      $s5 = "WXVZTVVUVX" fullword ascii /* base64 encoded string 'YuYMUTU' */
      $s6 = "ZYXZXSWZW" fullword ascii /* base64 encoded string 'avWIfV' */
      $s7 = "SZWVSZTVU" fullword ascii /* base64 encoded string 'eeRe5T' */
      $s8 = "VXVWUWVZYY" fullword ascii /* base64 encoded string 'UuVQeYa' */
      $s9 = "VSXZZYSVU" fullword ascii /* base64 encoded string 'IvYa%T' */
      $s10 = "VXUZUVWVU" fullword ascii /* base64 encoded string ']FTUeT' */
      $s11 = "SVVZZXZUVW" fullword ascii /* base64 encoded string 'IUYevTU' */
      $s12 = "USVZVSWVZ" fullword ascii /* base64 encoded string 'IVUIeY' */
      $s13 = "SWVVTVSVWWXZZVVV" fullword ascii /* base64 encoded string 'YUSU%VYvYUU' */
      $s14 = "VSXVUXXZS" fullword ascii /* base64 encoded string 'IuT]vR' */
      $s15 = "WSVZYWZWWW" fullword ascii /* base64 encoded string 'Y%YafVY' */
      $s16 = "XUSZXXVVW" fullword ascii /* base64 encoded string 'Q&W]UV' */
      $s17 = "ZWZWZVZWWWZ" fullword ascii /* base64 encoded string 'efVeVVYf' */
      $s18 = "STZVYVVZYS" fullword ascii /* base64 encoded string 'I6UaUYa' */
      $s19 = "ZWZWYSZXUZ" fullword ascii /* base64 encoded string 'efVa&WQ' */
      $s20 = "SVVWWVVVWW" fullword ascii /* base64 encoded string 'IUVYUUY' */
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "4e03b8b675969416fb0d10e8ab11f7c2" or ( 1 of ($x*) or 12 of them ) )
}


rule find_bat_14335 {
	meta:
		description = "Find.bat using AdFind"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2022/09/12/dead-or-alive-an-emotet-story/"
		date = "2022-09-12"
		hash1 = "5a5c601ede80d53e87e9ccb16b3b46f704e63ec7807e51f37929f65266158f4c"
	strings:
		$x1 = "find.exe" nocase wide ascii
				
		$s1 = "objectcategory" nocase wide ascii
		$s2 = "person" nocase wide ascii
		$s3 = "computer" nocase wide ascii
		$s4 = "organizationalUnit" nocase wide ascii
		$s5 = "trustdmp" nocase wide ascii
	condition:
		filesize < 1000
		and 1 of ($x*)
		and 4 of ($s*)
}


rule adfind_14335 {
   meta:
        description = "Find.bat using AdFind"
	author = "The DFIR Report"
	reference = "https://thedfirreport.com/2022/09/12/dead-or-alive-an-emotet-story/"
	date = "2022-09-12"
        hash1 = "b1102ed4bca6dae6f2f498ade2f73f76af527fa803f0e0b46e100d4cf5150682"


   strings:
        $x1 = "joeware.net" nocase wide ascii			
	$s1 = "xx.cpp" nocase wide ascii
	$s2 = "xxtype.cpp" nocase wide ascii
	$s3 = "Joe Richards" nocase wide ascii
	$s4 = "RFC 2253" nocase wide ascii
	$s5 = "RFC 2254" nocase wide ascii
 
  condition:
      uint16(0) == 0x5a4d and filesize < 2000KB
      and 1 of ($x*)
	  or 4 of ($s*)
}


rule p_bat_14335 {
   meta:
        description = "Finding bat files that is used for enumeration"
	author = "The DFIR Report"
	reference = "https://thedfirreport.com/2022/09/12/dead-or-alive-an-emotet-story/"
	date = "2022-09-12"  


   strings:
        				
		$a1 = "for /f %%i in" nocase wide ascii
		$a2 = "do ping %%i" nocase wide ascii
		$a3 = "-n 1 >>" nocase wide ascii
		$a4 = "res.txt" nocase wide ascii		
 
  condition:
      filesize < 2000KB
      and all of ($a*)
}

