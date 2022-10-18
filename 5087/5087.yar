/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-09-01
Identifier: Case 5087 BazarLoader to Conti Ransomware in 32 Hours
Reference: https://thedfirreport.com/2021/09/13/bazarloader-to-conti-ransomware-in-32-hours/
*/

/* Rule Set ----------------------------------------------------------------- */

rule case_5087_start_bat { 
   meta: 
      description = "Files - file start.bat" 
      author = "The DFIR Report" 
      reference = "https://thedfirreport.com" 
      date = "2021-08-30" 
      hash1 = "63de40c7382bbfe7639f51262544a3a62d0270d259e3423e24415c370dd77a60" 
   strings: 
      $x1 = "powershell.exe Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force" fullword ascii 
      $x2 = "powershell.exe -executionpolicy remotesigned -File .\\Get-DataInfo.ps1 %method" fullword ascii 
      $x3 = "powershell.exe -executionpolicy remotesigned -File .\\Get-DataInfo.ps1 %1)" fullword ascii 
      $s4 = "set /p method=\"Press Enter for collect [all]:  \"" fullword ascii 
      $s5 = "echo \"Please select a type of info collected:\"" fullword ascii 
      $s6 = "echo \"all ping disk soft noping nocompress\"" fullword ascii 
   condition: 
      filesize < 1KB and all of them 
} 



rule case_5087_3 { 
   meta: 
      description = "Files - file 3.exe" 
      author = "The DFIR Report" 
      reference = "https://thedfirreport.com" 
      date = "2021-08-30" 
      hash1 = "37b264e165e139c3071eb1d4f9594811f6b983d8f4b7ef1fe56ebf3d1f35ac89" 
   strings: 
      $s1 = "https://sectigo.com/CPS0" fullword ascii 
      $s2 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii 
      $s3 = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii 
      $s4 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii 
      $s5 = "        <requestedExecutionLevel level=\"asInvoker\"/>" fullword ascii 
      $s6 = "http://ocsp.sectigo.com0" fullword ascii 
      $s7 = "2http://crt.sectigo.com/SectigoRSACodeSigningCA.crt0#" fullword ascii 
      $s8 = "2http://crl.sectigo.com/SectigoRSACodeSigningCA.crl0s" fullword ascii 
      $s9 = "ealagi@aol.com0" fullword ascii 
      $s10 = "bhfatmxx" fullword ascii 
      $s11 = "orzynoxl" fullword ascii 
      $s12 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii 
      $s13 = "      <!--The ID below indicates application support for Windows 8.1 -->" fullword ascii 
      $s14 = "      <!--The ID below indicates application support for Windows 8 -->" fullword ascii 
      $s15 = "O:\\-e%" fullword ascii 
      $s16 = "      <!--The ID below indicates application support for Windows 10 -->" fullword ascii 
      $s17 = "      <!--The ID below indicates application support for Windows 7 -->" fullword ascii 
      $s18 = "      <!--The ID below indicates application support for Windows Vista -->" fullword ascii 
      $s19 = "  <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" fullword ascii 
      $s20 = "  </compatibility>" fullword ascii 
   condition: 
      uint16(0) == 0x5a4d and filesize < 1000KB and 8 of them 
} 

rule case_5087_7A86 { 
   meta: 
      description = "Files - file 7A86.dll" 
      author = "The DFIR Report" 
      reference = "https://thedfirreport.com" 
      date = "2021-08-30" 
      hash1 = "9d63a34f83588e208cbd877ba4934d411d5273f64c98a43e56f8e7a45078275d" 
   strings: 
      $s1 = "ibrndbiclw.dll" fullword ascii 
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii 
      $s3 = "Type Descriptor'" fullword ascii 
      $s4 = "operator co_await" fullword ascii 
   condition: 
      uint16(0) == 0x5a4d and filesize < 500KB and all of them 
} 

 rule case_5087_24f692b4ee982a145abf12c5c99079cfbc39e40bd64a3c07defaf36c7f75c7a9 { 
   meta: 
      description = "Files - file 24f692b4ee982a145abf12c5c99079cfbc39e40bd64a3c07defaf36c7f75c7a9.exe" 
      author = "The DFIR Report" 
      reference = "https://thedfirreport.com" 
      date = "2021-08-30" 
      hash1 = "24f692b4ee982a145abf12c5c99079cfbc39e40bd64a3c07defaf36c7f75c7a9" 
   strings: 
      $s1 = "fbtwmjnrrovmd.dll" fullword ascii 
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii 
      $s3 = " Type Descriptor'" fullword ascii 
      $s4 = "operator co_await" fullword ascii 
   condition: 
      uint16(0) == 0x5a4d and filesize < 900KB and all of them 
}
