/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2022-02-20
   Identifier: Case 8734 Qbot and Zerologon Lead To Full Domain Compromise
   Reference: https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/
*/


/* Rule Set ----------------------------------------------------------------- */


import "pe"


rule qbot_8734_payload_dll {
   meta:
      description = "files - file e2bc969424adc97345ac81194d316f58da38621aad3ca7ae27e40a8fae582987"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-02-20"
      hash1 = "e2bc969424adc97345ac81194d316f58da38621aad3ca7ae27e40a8fae582987"
   strings:
      $s1 = "Terfrtghygine.dll" fullword ascii
      $s2 = "Winamp can read extended metadata for titles. Choose when this happens:" fullword wide /* Goodware String - occured 1 times */
      $s3 = "Read metadata when file(s) are loaded into Winamp" fullword wide /* Goodware String - occured 1 times */
      $s4 = "Use advanced title formatting when possible" fullword wide /* Goodware String - occured 1 times */
      $s5 = "PQVW=!?" fullword ascii
      $s6 = "Show underscores in titles as spaces" fullword wide /* Goodware String - occured 1 times */
      $s7 = "Advanced title display format :" fullword wide /* Goodware String - occured 1 times */
      $s8 = "CreatePaint" fullword ascii
      $s9 = "PQRVW=2\"" fullword ascii
      $s10 = "Advanced Title Formatting" fullword wide /* Goodware String - occured 1 times */
      $s11 = "Read metadata when file(s) are played or viewed in the playlist editor" fullword wide /* Goodware String - occured 1 times */
      $s12 = "Show '%20's in titles as spaces" fullword wide /* Goodware String - occured 1 times */
      $s13 = "Example : \"%artist% - %title%\"" fullword wide /* Goodware String - occured 1 times */
      $s14 = "PQRVW=g" fullword ascii
      $s15 = "PQRW=e!" fullword ascii
      $s16 = "ATF Help" fullword wide /* Goodware String - occured 1 times */
      $s17 = "(this can be slow if a large number of files are added at once)" fullword wide /* Goodware String - occured 1 times */
      $s18 = "PQRVW=$" fullword ascii
      $s19 = "Metadata Reading" fullword wide /* Goodware String - occured 1 times */
      $s20 = "Other field names: %artist%, %album%, %title%, %track%, %year%, %genre%, %comment%, %filename%, %disc%, %rating%, ..." fullword wide /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "aa8a9db10fba890f8ef9edac427eab82" and pe.exports("CreatePaint") or 8 of them )
}


rule qbot_dll_8734 {
   meta:
      description = "files - qbot.dll"
      author = "TheDFIRReport"
      reference = "QBOT_DLL"
      date = "2021-12-04"
      hash1 = "4d3b10b338912e7e1cbade226a1e344b2b4aebc1aa2297ce495e27b2b0b5c92b"
   strings:
      $s1 = "Execute not supported: %sfField '%s' is not the correct type of calculated field to be used in an aggregate, use an internalcalc" wide
      $s2 = "IDAPI32.DLL" fullword ascii
      $s3 = "ResetUsageDataActnExecute" fullword ascii
      $s4 = "idapi32.DLL" fullword ascii
      $s5 = "ShowHintsActnExecute" fullword ascii
      $s6 = "OnExecute@iG" fullword ascii
      $s7 = "OnExecutexnD" fullword ascii
      $s8 = "ShowShortCutsInTipsActnExecute" fullword ascii
      $s9 = "ResetActnExecute " fullword ascii
      $s10 = "RecentlyUsedActnExecute" fullword ascii
      $s11 = "LargeIconsActnExecute" fullword ascii
      $s12 = "ResetActnExecute" fullword ascii
      $s13 = "OnExecute<" fullword ascii
      $s14 = "TLOGINDIALOG" fullword wide
      $s15 = "%s%s:\"%s\";" fullword ascii
      $s16 = ":\":&:7:?:C:\\:" fullword ascii /* hex encoded string '|' */
      $s17 = "LoginPrompt" fullword ascii
      $s18 = "TLoginDialog" fullword ascii
      $s19 = "OnLogin" fullword ascii
      $s20 = "Database Login" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      12 of them
}
