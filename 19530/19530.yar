/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2024-02-18
   Identifier: Case 19530
   Reference: https://thedfirreport.com
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule case_19530_implied_employment_agreement {
   meta:
      description = "file implied employment agreement 24230.js"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2024-02-18"
      hash1 = "f94048917ac75709452040754bb3d1a0aff919f7c2b4b42c5163c7bdb1fbf346"
   strings:
      $s1 = "dx = Math.pow(10, Math.round(Math.log(dx) / Math.LN10) - 1);" fullword ascii
      $s2 = "return -Math.log(-x) / Math.LN10;" fullword ascii
      $s3 = "return d3.format(\",.\" + Math.max(0, -Math.floor(Math.log(d3_scale_linearTickRange(domain, m)[2]) / Math.LN10 + .01)) + \"f\");" ascii
      $s4 = "var n = 1 + Math.floor(1e-15 + Math.log(x) / Math.LN10);" fullword ascii
      $s5 = "for (i = 0, n = q.length; (m = d3_interpolate_number.exec(a)) && i < n; ++i) {" fullword ascii
      $s6 = "* - Redistributions in binary form must reproduce the above copyright notice," fullword ascii
      $s7 = "* - Neither the name of the author nor the names of contributors may be used to" fullword ascii
      $s8 = "thresholds.length = Math.max(0, q - 1);" fullword ascii
      $s9 = "* Brewer (http://colorbrewer.org/). See lib/colorbrewer for more information." fullword ascii
      $s10 = "chord.target = function(v) {" fullword ascii
      $s11 = "diagonal.target = function(x) {" fullword ascii
      $s12 = "return c.charAt(c.length - 1) === \"%\" ? Math.round(f * 2.55) : f;" fullword ascii
      $s13 = "return Math.log(x) / Math.LN10;" fullword ascii
      $s14 = "step = Math.pow(10, Math.floor(Math.log(span / m) / Math.LN10))," fullword ascii
      $s15 = "var match = d3_format_re.exec(specifier)," fullword ascii
      $s16 = "m1 = /([a-z]+)\\((.*)\\)/i.exec(format);" fullword ascii
      $s17 = "for (i = 0; m = d3_interpolate_number.exec(b); ++i) {" fullword ascii
      $s18 = "* TERMS OF USE - EASING EQUATIONS" fullword ascii
      $s19 = "var d3_mouse_bug44083 = /WebKit/.test(navigator.userAgent) ? -1 : 0;" fullword ascii
      $s20 = "* - Redistributions of source code must retain the above copyright notice, this" fullword ascii
   condition:
      uint16(0) == 0x6628 and filesize < 400KB and
      8 of them
}

rule case_19530_systembc_s5 {
   meta:
      description = "file s5.ps1"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2024-02-18"
      hash1 = "49b75f4f00336967f4bd9cbccf49b7f04d466bf19be9a5dec40d0c753189ea16"
   strings:
      $x1 = "Set-ItemProperty -Path $path_reg -Name \"socks_powershell\" -Value \"Powershell.exe -windowstyle hidden -ExecutionPolicy Bypass " ascii
      $x2 = "Set-ItemProperty -Path $path_reg -Name \"socks_powershell\" -Value \"Powershell.exe -windowstyle hidden -ExecutionPolicy Bypass " ascii
      $s3 = "Remove-ItemProperty -Path \"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" -Name \"socks_powershell\"" fullword ascii
      $s4 = "$end = [int](Get-Date -uformat \"%s\")" fullword ascii
      $s5 = "$st = [int](Get-Date -uformat \"%s\")" fullword ascii
      $s6 = "$path_reg = \"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"" fullword ascii
      $s7 = "$sArray[0] = New-Object System.Net.Sockets.TcpClient( $ipaddress, $dport)" fullword ascii
      $s8 = "$sArray[$perem2] = New-Object System.Net.Sockets.TcpClient( $ip, $newport)" fullword ascii
      $s9 = "[string]$ip = [System.Text.Encoding]::ASCII.GetString($fB)" fullword ascii
      $s10 = "$ipaddress = '91.92.136.20'" fullword ascii
      $s11 = "$rc1 = [math]::Floor(($rc -band 0x0000ff00) * [math]::Pow(2,-8))" fullword ascii
      $s12 = "$o1 = [math]::Floor(($os -band 0x0000ff00) * [math]::Pow(2,-8))" fullword ascii
      $s13 = "$Time = $end - $st" fullword ascii
      $s14 = "elseif ($bf0[4 + 3] -eq 0x01 -as[byte])" fullword ascii
      $s15 = "$buff0[$start + $perem3] = $perem5 -as [byte]" fullword ascii
      $s16 = "Start-Sleep -s 180" fullword ascii
      $s17 = "[string]$ip = \"{0}.{1}.{2}.{3}\" -f $a, $b, $c, $ip" fullword ascii
      $s18 = "For ($i=0; $i -ne $perem9; $i++) { $bf0[$i + $perem0] = $rb[$i + $perem11] }" fullword ascii
      $s19 = "if ($bf0[2 + 0] -eq 0x00 -as[byte] -and $bf0[2 + 1] -eq 0x00 -as[byte])" fullword ascii
      $s20 = "if ($bf0[0 + 0] -eq 0x00 -as[byte] -and $bf0[0 + 1] -eq 0x00 -as[byte])" fullword ascii
   condition:
      uint16(0) == 0x7824 and filesize < 40KB and
      1 of ($x*) and 4 of them
}

rule case_19530_CS_beacon {
   meta:
      description = "file 5d78365.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2024-02-18"
      hash1 = "aad75498679aada9ee2179a8824291e3b4781d5683c2fa5b3ec92267ce4a4a33"
   strings:
      $s1 = "%c%c%c%c%c%c%c%c%cnetsvc\\%d" fullword ascii
      $s2 = "WinHttpSvc" fullword ascii
      $s3 = "+  cl_+" fullword ascii
      $s4 = "lsxkrb" fullword ascii
      $s5 = "vDqPSzK6" fullword ascii
      $s6 = ":b(l%h%" fullword ascii
      $s7 = "lszkrb" fullword ascii
      $s8 = "10.0.19041.1266 (WinBuild.160101.0800)" fullword wide
      $s9 = "sMgJkl?sW" fullword ascii
      $s10 = "@}0.Fpn" fullword ascii
      $s11 = "dwPS@%oNB" fullword ascii
      $s12 = "RRcB(jE" fullword ascii
      $s13 = "Rwco)pS" fullword ascii
      $s14 = "cxjI6NB" fullword ascii
      $s15 = "rgNg(>P" fullword ascii
      $s16 = "jawXX_3" fullword ascii
      $s17 = "xSsckrb" fullword ascii
      $s18 = "{uaNB,Pe|K" fullword ascii
      $s19 = "DwcR+dS" fullword ascii
      $s20 = "YwcH*gC" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      ( pe.imphash() == "49145e436aa571021bb1c7b727f8b049" or 8 of them )
}


