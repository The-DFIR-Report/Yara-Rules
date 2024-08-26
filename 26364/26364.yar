/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2024-08-20
   Identifier: Case 26364
   Reference: https://thedfirreport.com
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule case_26364_cobalt_strike_smb_beacon {
   meta:
      description = "Case 26364 - file e225857.exe Cobalt Strike SMB beacon"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2024/08/26/blacksuit-ransomware/"
      date = "2024-08-20"
      hash1 = "f474241a5d082500be84a62f013bc2ac5cde7f18b50bf9bb127e52bf282fffbf"
   strings:
      $s1 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" fullword ascii
      $s2 = "IplPi\\lHiX" fullword ascii
      $s3 = "!IToX|\\M\\8\\" fullword ascii
      $s4 = "lXixf`ix" fullword ascii
      $s5 = "lXitnXix" fullword ascii
      $s6 = "MTnHiD$" fullword ascii
      $s7 = "mXGPnXiP$" fullword ascii
      $s8 = "DlPi,lHi$" fullword ascii
      $s9 = "nHilf!" fullword ascii
      $s10 = "hHit\"Xit" fullword ascii
      $s11 = "hPitlXi" fullword ascii
      $s12 = "/I^lXiPnXiP$" fullword ascii
      $s13 = "MTnHi|$" fullword ascii
      $s14 = "nXiDf$U)" fullword ascii
      $s15 = "IUlXi|nXi|$" fullword ascii
      $s16 = "nHixnhiHn`it" fullword ascii
      $s17 = "MTnHiH$" fullword ascii
      $s18 = "lPitlXi|" fullword ascii
      $s19 = "XeYv ,8?[" fullword ascii
      $s20 = "lXitf`it" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      ( pe.imphash() == "bed5688a4a2b5ea6984115b458755e90" or pe.imphash() == "1b2b0fc8f126084d18c48b4f458c798b" or 8 of them )
}


rule case_26364_Get_DataInfo {
   meta:
      description = "Case 26364 - file Get-DataInfo.ps1"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2024/08/26/blacksuit-ransomware/"
      date = "2024-08-20"
      hash1 = "6f5f3c8aa308819337a2f69d453ab2f6252491aa0ccc94a8364d0c3c10533173"
   strings:
      $x1 = "$computername = Get-Content \".\\result\\livePCs.txt\" -ReadCount 0" fullword ascii
      $x2 = "$computername = Get-Content \".\\result\\livePCs.txt\" -ReadCount 0  " fullword ascii
      $s3 = "'disk' {Test-LHosts; Get-Diskinfo | Export-Csv -Path .\\result\\Disk.csv -NoTypeInformation; Compress-Result}" fullword ascii
      $s4 = "'all' {Test-LHosts; Get-Diskinfo | Export-Csv -Path .\\result\\Disk.csv -NoTypeInformation; Get-Software; Compress-Result}" fullword ascii
      $s5 = "default {Test-LHosts; Get-Diskinfo | Export-Csv -Path .\\result\\Disk.csv -NoTypeInformation; Get-Software; Compress-Result}" fullword ascii
      $s6 = "'nocompress' {Test-LHosts; Get-Diskinfo | Export-Csv -Path .\\result\\Disk.csv -NoTypeInformation; Get-Software}" fullword ascii
      $s7 = "}else{Add-Content \"$computer is not reachable\" -path .\\result\\error.txt}" fullword ascii
      $s8 = "$testcomputers = Get-Content -Path $compsfile -ReadCount 0" fullword ascii
      $s9 = "'noping' {Get-Diskinfo | Export-Csv -Path .\\result\\Disk.csv -NoTypeInformation; Get-Software; Compress-Result}" fullword ascii
      $s10 = "Try{Get-WmiObject Win32_LogicalDisk -filter \"DriveType=3\" -computer $computer | Select SystemName,DeviceID,@{Name=\"Size(GB)\"" ascii
      $s11 = "Add-Content -value $computer -path .\\result\\livePCs.txt" fullword ascii
      $s12 = "Add-Content -value $computer -path .\\result\\deadPCs.txt" fullword ascii
      $s13 = "Invoke-Expression \"& '.\\7z.exe' a '$typearchiv' '$destination' '$CompressionLevel' -aoa '$Source'\"" fullword ascii
      $s14 = "Catch {Add-Content \"$computer is not reachable\" -path .\\result\\error.txt}" fullword ascii
      $s15 = "write-host -foregroundcolor cyan \"Testing Connection complete\"" fullword ascii
      $s16 = "Try{Get-WmiObject Win32_LogicalDisk -filter \"DriveType=3\" -computer $computer | Select SystemName,DeviceID,@{Name=\"Size(GB)\"" ascii
      $s17 = "Write-Progress  \"Testing Connections\" -PercentComplete $testcomputer_progress -Status \"Percent Complete - $testcomputer_progr" ascii
      $s18 = "Write-Progress  \"Testing Connections\" -PercentComplete $testcomputer_progress -Status \"Percent Complete - $testcomputer_prog" fullword ascii
      $s19 = "'soft' {Test-LHosts; Get-Software; Compress-Result}" fullword ascii
      $s20 = "}Catch{Add-Content \"$registry\" -path .\\result\\error.txt}" fullword ascii
   condition:
      uint16(0) == 0x5323 and filesize < 20KB and
      1 of ($x*) and 4 of them
}


rule case_26364_socks32_systembc {
   meta:
      description = "Case 26364 - file socks32.exe SystemBC executable"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2024/08/26/blacksuit-ransomware/"
      date = "2024-08-20"
      hash1 = "9493b512d7d15510ebee5b300c55b67f9f2ff1dda64bddc99ba8ba5024113300"
   strings:
      $x1 = "powershell.exe -windowstyle hidden -Command \"& '%s'\"" fullword ascii
      $s2 = "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0" fullword ascii
      $s3 = "FGET %s HTTP/1.0" fullword ascii
      $s4 = "HOST1:137.220.61.94" fullword ascii
      $s5 = "HOST2:137.220.61.94" fullword ascii
      $s6 = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" fullword ascii
      $s7 = "randomdata" fullword ascii
      $s8 = "PORT1:4001" fullword ascii
      $s9 = "GNPj2ht@@" fullword ascii
      $s10 = "PSQRWVh" fullword ascii
      $s11 = "7*80868<8B8H8N8T8Z8`8f8l8r8x8~8" fullword ascii /* Goodware String - occured 2 times */
      $s12 = "9 9&9,92989>9D9J9P9V9\\9b9h9n9" fullword ascii /* Goodware String - occured 3 times */
      $s13 = "Pj2ht@@" fullword ascii
      $s14 = "SQRWVi" fullword ascii
      $s15 = "Wj2ht@@" fullword ascii
      $s16 = "j2ht@@" fullword ascii
      $s17 = "w^_ZY[X" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and
      ( pe.imphash() == "d66000edfed0a9938162b2b453ffa516" or ( 1 of ($x*) or 4 of them ) )
}


rule case_26364_qwe {
   meta:
      description = "Case 26364 - file qwe.exe BlackSuit ransomware binary"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2024/08/26/blacksuit-ransomware/"
      date = "2024-08-20"
      hash1 = "60dcbfb30802e7f4c37c9cdfc04ddb411060918d19e5b309a5be6b4a73c8b18a"
   strings:
      $s1 = "<requestedExecutionLevel level = 'asInvoker' uiAccess = 'false' />" fullword ascii
      $s2 = "readme.blacksuit.txt" fullword wide
      $s3 = "---END RSA PUBLIC KEY-----" fullword ascii
      $s4 = "Q0ZkwAQVIbDNhXd1WM0sgajkBlDCqo7/xN1J8tdN5RH7njgltu9TlY2D4/c//70IYfCi4SYUVCSpUiVec6b6crv//bwXa489J9e8iruZ0jfZ+A/+31QXqNm3vGGeExZh" ascii
      $s5 = "ugHzziMZidFzMjw/sBynX5F60q6cE/xQnLXsT03ku6uj9klgIqE58A5+5jxLCLU7NWouX6OIMRsK2jkyOIaeWmT2s5z76PaBebSracTWUedtZ2qz62U7PwqherErP16s" ascii
      $s6 = "FN81uoDozfxgUonhHA6TuD/iVHluiuZhwFt0OnFAhpqSJnLJsSWmce3rUwxpvKO2G8JQpNl63tIn0BTvVyz2OQ0QB4eZsq5WuYOPW0YIE5nCxzzDNRH49KL8BCw5TpIP" ascii
      $s7 = "nYm3jVJI5fY4IOIbbKpVJ0mJdkcyAbaBXekA33COOE3FVSL/k4WkYKsbXVumq7Z2xfHff1Q9KlhA1PaWP6vVPlQvXSKdZYUMcSStOce3RuYh2FBfVo7yWMMp0M6hTTC2" ascii
      $s8 = "-----BEGIN RSA PUBLIC KEY-----MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAre9g2v/YKJF5okac0aAy5iLq0A3bwH4je29tFyrN1mkhp0zafxMuNn" ascii
      $s9 = "-----BEGIN RSA PUBLIC KEY-----MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAre9g2v/YKJF5okac0aAy5iLq0A3bwH4je29tFyrN1mkhp0zafxMuNn" ascii
      $s10 = ".rdata$voltmd" fullword ascii
      $s11 = "D$lfff" fullword ascii /* Goodware String - occured 2 times */
      $s12 = "l$|9D$ " fullword ascii
      $s13 = "2'2-252H2R2X2i2t2z2" fullword ascii
      $s14 = ";*<5<;<R<X<" fullword ascii
      $s15 = "021G1S3{3" fullword ascii
      $s16 = "92:U:p:" fullword ascii
      $s17 = "hCW,tf" fullword ascii
      $s18 = "727C7q7" fullword ascii
      $s19 = "=1]1|1" fullword ascii
      $s20 = "2(252:2" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      ( pe.imphash() == "ecc488e51fbb2e01a7aac2b35d5f10bd" or 8 of them )
}

