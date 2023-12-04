rule yara_tor2mine {
   meta:
      description = "file java.exe"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/"
      date = "2023-12-02"
      hash1 = "74b6d14e35ff51fe47e169e76b4732b9f157cd7e537a2ca587c58dbdb15c624f"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s2 = "3~\"0\\25" fullword ascii /* hex encoded string '0%' */
      $s3 = "X'BF:\"" fullword ascii
      $s4 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s5 = "<BiNHQZG?" fullword ascii
      $s6 = "5%d:8\\" fullword ascii
      $s7 = "tJohdy7" fullword ascii
      $s8 = "0- vuyT]" fullword ascii
      $s9 = "wpeucv" fullword ascii
      $s10 = "kreczd" fullword ascii
      $s11 = "%DeK%o" fullword ascii
      $s12 = "i%eI%xS" fullword ascii
      $s13 = "s -mY'" fullword ascii
      $s14 = "mCVAvi2" fullword ascii
      $s15 = "**[Zu -" fullword ascii
      $s16 = "%TNz%_\"V" fullword ascii
      $s17 = " -reB6" fullword ascii
      $s18 = "OD.vbpyW" fullword ascii
      $s19 = ":I* &b" fullword ascii
      $s20 = "R?%Y%l" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule yara_bluesky_ransomware {
   meta:
      description = "file vmware.exe"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/"
      date = "2023-12-02"
      hash1 = "d4f4069b1c40a5b27ba0bc15c09dceb7035d054a022bb5d558850edfba0b9534"
   strings:
      $s1 = "040<0G0#1+111;1A1I1" fullword ascii
      $s2 = "VWjPSP" fullword ascii
      $s3 = "040J0O0" fullword ascii
      $s4 = "4Y:)m^." fullword ascii
      $s5 = ":6:I:O:}:" fullword ascii
      $s6 = "5.6G6t6" fullword ascii
      $s7 = ";%;N;X;c;r;" fullword ascii
      $s8 = "747h7h8" fullword ascii
      $s9 = "8K8S8m8" fullword ascii
      $s10 = ";#;.;9;D;" fullword ascii
      $s11 = "6%6+6G8M8" fullword ascii
      $s12 = "0\"0&0,02060<0B0F0u0" fullword ascii
      $s13 = "hQSqQh" fullword ascii
      $s14 = "QVhNkO" fullword ascii
      $s15 = "?+?3?G?T?" fullword ascii
      $s16 = ":-;<;k;" fullword ascii
      $s17 = "1%212H2" fullword ascii
      $s18 = "h@pVxh=" fullword ascii
      $s19 = ">Gfm_E1:" fullword ascii
      $s20 = "'1]1e1m1" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule WinRing0x64 {
   meta:
      description = "file WinRing0x64.sys"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/"
      date = "2023-12-02"
      hash1 = "11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5"
   strings:
      $s1 = "d:\\hotproject\\winring0\\source\\dll\\sys\\lib\\amd64\\WinRing0.pdb" fullword ascii
      $s2 = "WinRing0.sys" fullword wide
      $s3 = "timestampinfo@globalsign.com0" fullword ascii
      $s4 = "\"GlobalSign Time Stamping Authority1+0)" fullword ascii
      $s5 = "\\DosDevices\\WinRing0_1_2_0" fullword wide
      $s6 = "OpenLibSys.org" fullword wide
      $s7 = ".http://crl.globalsign.net/RootSignPartners.crl0" fullword ascii
      $s8 = "Copyright (C) 2007-2008 OpenLibSys.org. All rights reserved." fullword wide
      $s9 = "1.2.0.5" fullword wide
      $s10 = " Microsoft Code Verification Root0" fullword ascii
      $s11 = "\\Device\\WinRing0_1_2_0" fullword wide
      $s12 = "WinRing0" fullword wide
      $s13 = "hiyohiyo@crystalmark.info0" fullword ascii
      $s14 = "GlobalSign1+0)" fullword ascii
      $s15 = "Noriyuki MIYAZAKI1(0&" fullword ascii
      $s16 = "The modified BSD license" fullword wide
      $s17 = "RootSign Partners CA1" fullword ascii
      $s18 = "\\/.gJ&" fullword ascii
      $s19 = "031216130000Z" fullword ascii
      $s20 = "04012209" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      8 of them
}
