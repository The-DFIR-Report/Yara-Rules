/*
   YARA Rule Set
   Author: TheDFIRReport
   Date: 2024-01-09
   Identifier: 19772
   Reference: https://thedfirreport.com
*/

/* Rule Set ----------------------------------------------------------------- */

rule case_19772_csrss_cobalt_strike {
   meta:
      description = "19772 - file csrss.exe"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com"
      date = "2024-01-09"
      hash1 = "06bbb36baf63bc5cb14d7f097745955a4854a62fa3acef4d80c61b4fa002c542"
   strings:
      $x1 = "Invalid owner %s is already associated with %s=This control requires version 4.70 or greater of COMCTL32.DLL" fullword wide
      $s2 = "traydemo.exe" fullword ascii
      $s3 = "333330303030333333" ascii /* hex encoded string '330000333' */
      $s4 = "323232323233323232323233333333333333" ascii /* hex encoded string '222223222223333333' */
      $s5 = "333333333333333333333333333333333333333333333333333333333333333333333333" ascii /* hex encoded string '333333333333333333333333333333333333' */
      $s6 = "Borland C++ - Copyright 2002 Borland Corporation" fullword ascii
      $s7 = "@Cdiroutl@TCDirectoryOutline@GetChildNamed$qqrrx17System@AnsiStringl" fullword ascii
      $s8 = "2a1d2V1p1" fullword ascii /* base64 encoded string 'kWvWZu' */
      $s9 = "Separator\"Unable to find a Table of Contents" fullword wide
      $s10 = "EInvalidGraphicOperation4" fullword ascii
      $s11 = ")Failed to read ImageList data from stream(Failed to write ImageList data to stream$Error creating window device context" fullword wide
      $s12 = "%s: %s error" fullword ascii
      $s13 = "@TTrayIcon@GetAnimate$qqrv" fullword ascii
      $s14 = "ImageTypeh" fullword ascii
      $s15 = "42464:4`4d4 3" fullword ascii /* hex encoded string 'BFDMC' */
      $s16 = "333333333333333333333333(" fullword ascii /* hex encoded string '333333333333' */
      $s17 = ")\"\")\"\")#3232" fullword ascii /* hex encoded string '22' */
      $s18 = "OnGetItem(3B" fullword ascii
      $s19 = "@Cspin@TCSpinEdit@GetValue$qqrv" fullword ascii
      $s20 = "@Cspin@TCSpinButton@GetUpGlyph$qqrv" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule case_19772_svchost_nokoyawa_ransomware {
   meta:
      description = "19772 - file svchost.exe"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com"
      date = "2024-01-09"
      hash1 = "3c9f4145e310f616bd5e36ca177a3f370edc13cf2d54bb87fe99972ecf3f09b4"
   strings:
      $s1 = " ;3;!X" fullword ascii /* reversed goodware string 'X!;3; ' */
      $s2 = "bcdedit" fullword wide
      $s3 = "geKpgAX3" fullword ascii
      $s4 = "shutdown" fullword wide /* Goodware String - occured 93 times */
      $s5 = "k2mm7KvHl51n2LJDYLanAgM48OX97gkV" fullword ascii
      $s6 = "+TDPbuWCWNmcW0k=" fullword ascii
      $s7 = "4vEBlUlgJ5oeqmbpb9OSaQrQb8bRWNqP" fullword ascii
      $s8 = "2aDXUPxh3ZZ1x8tpfg6PxcMuUwWogOgQ" fullword ascii
      $s9 = "kfeCWydRqz8=" fullword ascii
      $s10 = "ZfrMxxDy" fullword ascii
      $s11 = "eLTuGYHd" fullword ascii
      $s12 = "wWIQZ5jJPZIiuDKxQVh0YO3HnzdOwirY" fullword ascii
      $s13 = "+IdWS+zG9rUG" fullword ascii
      $s14 = "0ZdUoZmp" fullword ascii
      $s15 = "SVWh$l@" fullword ascii
      $s16 = "Z2mJzxHFaRafgf4k/uTdeMKIMUpV/y81" fullword ascii
      $s17 = "GtKqGSOfNUOVIoMTk8bGZVchMddKIuTN" fullword ascii
      $s18 = "INMvjo3GzuQ6MTSJUg==" fullword ascii
      $s19 = "hilWGBcFwE80e5L9BXxCiRiE" fullword ascii
      $s20 = "gSMSrcOR" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      8 of them
}

rule case_19772_anydesk_id_tool {
   meta:
      description = "19772 - file GET_ID.bat"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com"
      date = "2024-01-09"
      hash1 = "eae2bce6341ff7059b9382bfa0e0daa337ea9948dd729c0c1e1ee9c11c1c0068"
   strings:
      $x1 = "for /f \"delims=\" %%i in ('C:\\ProgramData\\Any\\AnyDesk.exe --get-id') do set ID=%%i " fullword ascii
      $s2 = "echo AnyDesk ID is: %ID%" fullword ascii
   condition:
      uint16(0) == 0x6540 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule case_19772_anydesk_installer {
   meta:
      description = "19772 - file INSTALL.ps1"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com"
      date = "2024-01-09"
      hash1 = "b378c2aa759625de2ad1be2c4045381d7474b82df7eb47842dc194bb9a134f76"
   strings:
      $x1 = "    cmd.exe /c echo btc1000qwe123 | C:\\ProgramData\\Any\\AnyDesk.exe --set-password" fullword ascii
      $x2 = "    cmd.exe /c C:\\ProgramData\\AnyDesk.exe --install C:\\ProgramData\\Any --start-with-win --silent" fullword ascii
      $s3 = "    #reg add \"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist\" /v Inn" ascii
      $s4 = "    #reg add \"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist\" /v Inn" ascii
      $s5 = "    $url = \"http://download.anydesk.com/AnyDesk.exe\"" fullword ascii
      $s6 = "EG_DWORD /d 0 /f" fullword ascii
      $s7 = "    $file = \"C:\\ProgramData\\AnyDesk.exe\"" fullword ascii
      $s8 = "    $clnt = new-object System.Net.WebClient" fullword ascii
      $s9 = "    #net user AD \"2020\" /add" fullword ascii
      $s10 = "    # Download AnyDesk" fullword ascii
      $s11 = "    mkdir \"C:\\ProgramData\\Any\"" fullword ascii
      $s12 = "    $clnt.DownloadFile($url,$file)" fullword ascii
      $s13 = "    #net localgroup Administrators InnLine /ADD" fullword ascii
   condition:
      uint16(0) == 0x0a0d and filesize < 1KB and
      1 of ($x*) and 4 of them
}

