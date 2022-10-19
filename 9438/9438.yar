/* 
   YARA Rule Set 
   Author: The DFIR Report 
   Date: 2022-04-04
   Identifier: Case 9438 Stolen Images Campaign Ends in Conti Ransomware
   Reference: https://thedfirreport.com/2022/04/04/stolen-images-campaign-ends-in-conti-ransomware/
*/ 


/* Rule Set ----------------------------------------------------------------- */ 


rule cs_exe_9438 {
   meta:
      description = "9438 - file Faicuy4.exe"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2022/04/04/stolen-images-campaign-ends-in-conti-ransomware/"
      date = "2022-04-04"
      hash1 = "a79f5ce304707a268b335f63d15e2d7d740b4d09b6e7d095d7d08235360e739c"
   strings:
      $x1 = "C:\\Users\\Administrator\\Documents\\Visual Studio 2008\\Projects\\MUTEXES\\x64\\Release\\MUTEXES.pdb" fullword ascii
      $s2 = "mutexes Version 1.0" fullword wide
      $s3 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s4 = ".?AVCMutexesApp@@" fullword ascii
      $s5 = ".?AVCMutexesDlg@@" fullword ascii
      $s6 = "About mutexes" fullword wide
      $s7 = "Mutexes Sample" fullword wide
      $s8 = " 1992 - 2001 Microsoft Corporation.  All rights reserved." fullword wide
      $s9 = "&Process priority class:" fullword wide
      $s10 = " Type Descriptor'" fullword ascii
      $s11 = "&About mutexes..." fullword wide
      $s12 = " constructor or from DllMain." fullword ascii
      $s13 = ".?AVCDisplayThread@@" fullword ascii
      $s14 = "IsQ:\"P" fullword ascii
      $s15 = "CExampleThread" fullword ascii
      $s16 = ".?AVCCounterThread@@" fullword ascii
      $s17 = ".?AVCExampleThread@@" fullword ascii
      $s18 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s19 = "CDisplayThread" fullword ascii
      $s20 = "CCounterThread" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}


rule conti_dll_9438 {
   meta:
      description = "9438 - file x64.dll"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2022/04/04/stolen-images-campaign-ends-in-conti-ransomware/"
      date = "2022-04-04"
      hash1 = "8fb035b73bf207243c9b29d96e435ce11eb9810a0f4fdcc6bb25a14a0ec8cc21"
   strings:
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s2 = "conti_v3.dll" fullword ascii
      $s3 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s4 = "api-ms-win-core-processthreads-l1-1-2" fullword wide
      $s5 = "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
      $s6 = " Type Descriptor'" fullword ascii
      $s7 = "operator \"\" " fullword ascii
      $s8 = "operator co_await" fullword ascii
      $s9 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s10 = "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
      $s11 = "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
      $s12 = "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
      $s13 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s14 = " Base Class Descriptor at (" fullword ascii
      $s15 = " Class Hierarchy Descriptor'" fullword ascii
      $s16 = "bad array new length" fullword ascii
      $s17 = " Complete Object Locator'" fullword ascii
      $s18 = ".data$r" fullword ascii
      $s19 = " delete[]" fullword ascii
      $s20 = "  </trustInfo>" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      all of them
}
