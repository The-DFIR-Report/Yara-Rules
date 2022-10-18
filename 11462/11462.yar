/* 
   YARA Rule Set 
   Author: The DFIR Report 
   Date: 2022-05-09 
   Identifier: Case 11462 SEO Poisoning – A Gootloader Story
   Reference: https://thedfirreport.com/2022/05/09/seo-poisoning-a-gootloader-story/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule olympus_plea_agreement_34603_11462 {
   meta:
      description = "file olympus_plea_agreement 34603 .js"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-05-01"
      hash1 = "6e141779a4695a637682d64f7bc09973bb82cd24211b2020c8c1648cdb41001b"
   strings:
      $s1 = "// https://web.archive.org/web/20141116233347/http://fluidproject.org/blog/2008/01/09/getting-setting-and-removing-tabindex-valu" ascii
      $s2 = "// Related ticket - https://bugzilla.mozilla.org/show_bug.cgi?id=687787" fullword ascii
      $s3 = "*    - AFTER param serialization (s.data is a string if s.processData is true)" fullword ascii
      $s4 = "* https://jquery.com/" fullword ascii
      $s5 = "* https://sizzlejs.com/" fullword ascii
      $s6 = "target.length = j - 1;" fullword ascii
      $s7 = "// Remove auto dataType and get content-type in the process" fullword ascii
      $s8 = "process.stackTrace = jQuery.Deferred.getStackHook();" fullword ascii
      $s9 = "* 5) execution will start with transport dataType and THEN continue down to \"*\" if needed" fullword ascii
      $s10 = "// https://web.archive.org/web/20141116233347/http://fluidproject.org/blog/2008/01/09/getting-setting-and-removing-tabindex-valu" ascii
      $s11 = "// We eschew Sizzle here for performance reasons: https://jsperf.com/getall-vs-sizzle/2" fullword ascii
      $s12 = "if ( s.data && s.processData && typeof s.data !== \"string\" ) {" fullword ascii
      $s13 = "} else if ( s.data && s.processData &&" fullword ascii
      $s14 = "if ( s.data && ( s.processData || typeof s.data === \"string\" ) ) {" fullword ascii
      $s15 = "rcssNum.exec( jQuery.css( elem, prop ) );" fullword ascii
      $s16 = "// Related ticket - https://bugs.chromium.org/p/chromium/issues/detail?id=449857" fullword ascii
      $s17 = "jQuery.inArray( \"script\", s.dataTypes ) > -1 &&" fullword ascii
      $s18 = "while ( ( match = rheaders.exec( responseHeadersString ) ) ) {" fullword ascii
      $s19 = "targets.index( cur ) > -1 :" fullword ascii
      $s20 = "* - finds the right dataType (mediates between content-type and expected dataType)" fullword ascii
   condition:
      uint16(0) == 0x2a2f and filesize < 900KB and
      8 of them
}

rule Invoke_WMIExec_11462 {
   meta:
      description = "file Invoke-WMIExec.ps1"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-05-01"
      hash1 = "c4939f6ad41d4f83b427db797aaca106b865b6356b1db3b7c63b995085457222"
   strings:
      $x1 = "Invoke-WMIExec -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Command \"comman" ascii
      $x2 = "Invoke-WMIExec -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Command \"comman" ascii
      $x3 = "Write-Output \"[+] Command executed with process ID $target_process_ID on $target_long\"" fullword ascii
      $x4 = "Invoke-WMIExec -Target 192.168.100.20 -Username administrator -Hash F6F38B793DB6A94BA04A52F1D3EE92F0" fullword ascii
      $s5 = "$target_address_list = [System.Net.Dns]::GetHostEntry($target_long).AddressList" fullword ascii
      $s6 = "$WMI_session_key_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostna" ascii
      $s7 = "Execute a command." fullword ascii
      $s8 = "$packet_DCOMRemoteCreateInstance.Add(\"IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesProcessReques" fullword ascii
      $s9 = "$packet_DCOMRemoteCreateInstance.Add(\"IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPrivateHeader" fullword ascii
      $s10 = "$packet_DCOMRemoteCreateInstance.Add(\"IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesCommonHeader\"" fullword ascii
      $s11 = "$packet_DCOMRemoteCreateInstance.Add(\"IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPrivateHeader\"," ascii
      $s12 = "$packet_DCOMRemoteCreateInstance.Add(\"IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesProcessRequestFl" ascii
      $s13 = "$packet_DCOMRemoteCreateInstance.Add(\"IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesCommonHeader\",[" ascii
      $s14 = "$target_process_ID = Get-UInt16DataLength 1141 $WMI_client_receive" fullword ascii
      $s15 = "$hostname_length = [System.BitConverter]::GetBytes($auth_hostname.Length + 1)" fullword ascii
      $s16 = "Write-Verbose \"[*] Attempting command execution\"" fullword ascii
      $s17 = "$process_ID = [System.Diagnostics.Process]::GetCurrentProcess() | Select-Object -expand id" fullword ascii
      $s18 = "$auth_NTLM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_host" fullword ascii
      $s19 = "$auth_LM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostna" fullword ascii
      $s20 = "[Byte[]]$packet_private_header = [System.BitConverter]::GetBytes($packet_target_unicode.Length + 40) + 0x00,0x00,0x00,0x00" fullword ascii
   condition:
      uint16(0) == 0x7566 and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule mi_mimikatz_11462 {
   meta:
      description = "Mimikatz - file mi.ps1"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-05-01"
      hash1 = "d00edf5b9a9a23d3f891afd51260b3356214655a73e1a361701cda161798ea0b"
   strings:
      $x1 = "$best64code = \"==gCNkydtdnbrpXbttmc01mazp2bkgCWFlkCNkSKoo3ZtNnatpHayBHJuMXb3RHanNne1FXarhGJo4Wa0R3b3Fnerl3a3RiLr5GcnBHcutmcnpGd" ascii
      $s2 = "lFM5cmbFVFMatSYLlTdTN2QCdXZyg2QsJVYGFEZiJERBV3T0ZVaYJGZZx2Kx4GSXxGdll1LSJ2R5F2d5J3N3VjSRtUZzgDUmpFOap1TwI3bKpHVDFlNL9GUQJTdwYUUr" ascii
      $s3 = "JFT0omerhFawNXbDVVcIdXZ1REOyMUVXBHVZpWZvUGN6dUMp9ycysCbtBXY5IUVSFVbiNXVtJUYVRFeD5mVYtEMIt0SiB3blZmTHlUWrUmV4RXdr80bw12QuVTQtx2LV" ascii
      $s4 = "x0dGlHUFpUYhV1YXVjR4N1b3p0cVRTTj10TxRFNxhnVEdHd5lGWPNTNFdjexRkNzl2MPtie0RWcnJXQ3djbIN0didHMzJTM5NmS01GaB50Z2VGSJVFOyZGd5hlN1BDMR" ascii
      $s5 = "R1TVhlRO10QXtiU4s2UrNEeXp1QDFzblRHb2UmZLFTdsJFR2BDcmdVesdnQKVWZ21GOQ5kaTdGTRJ1UXNzMVdDU4NHa0p0V3MDeEVFaExEcpBVQzQlY5g0bRV0N1lkQq" ascii
      $s6 = "RUUERUNw5UdSZ3bpp0cVVmeRpVVMx2R1ETZIZzYGhEd6J3VidHT3IUMUhHasR3cwAnM2sST5pUZiNVcjFlcSR3cTJkcmdzKZhkTzNGWzJmZ5N1a6lGbZFXSvEzMFBzRa" ascii
      $s7 = "lnMkxERH9EMiRmW4k2doBDS6dXdLlDM4VmRrlTWwMmSmFnNCV1YLdjN0sCUp9WST9SYHlkYaRWb5R3L0oVNn50am9EU6hkV0InYCNmWv4WTktUSxdnW0gET25GNxsWO4" ascii
      $s8 = "NzTyIXSJdFMip1ZrNVY1VzQStCVatEdm92ZU1Wc09SYNt0LRBnYPlEchV1RJN3ZLBlVtRlM2FDNWR0RSZ3d30mUNpHWD52SQFTNQtiS2kEalx0dll3UzQ2NGVEVIl0YT" ascii
      $s9 = "hzQ0QVYxhXWNdDN2lzd0JUR582TUhzaCJmVQhHaLp0c5VkWpNnQhh2QhJDO3oVSwczUkR0MyMkcwAldwJDbOd0SNJEVil0QVF3NGFkez5UYMZUQzgUM3gFOGhGRzU2Vw" ascii
      $s10 = "5mMnVDcohGWUVmbjlDWHFmVv8SY3ZGTrdja3k2TOd3KMBlUstmWrNzYyQzKwIzKzknQYlzKrknYlJndTFleDdnWV5Uc04kNYRldll3LaJjckBTMVp0cPZlZ1Y0MpZkS1" ascii
      $s11 = "F0KtlDetp0c4BnaBVXWERnczUWRPN2KDVTMkh1dFdFaKNmYKRGMrMHan5UbrRGMzIXcvlFe1J0Z0dUMPRFSvlndo9mSkpWQTV1SyNFZLFHRnVWRP5EcjJGcBp3L1c3am" ascii
      $s12 = "QWb5Z0UhJFUwgETQdGMxATdUdXcXRHcTVTMrQEe6JEWBxUTVhGR1hGULp1Vx8UQLRncYBnaN9mVDBFazcnbRFTSJpXTuZDS4dTd0l0ZGJTUYlUSwIEcIFDcnF0Zip0cJ" ascii
      $s13 = "RVUm9GcjV0MwQGV3NGWxMWVSRDMNJHevdUMpFHVxMXQyp3VrcHVJdGeJtUQvMXb3dUZ4cERUdHN3FFSQ5kdL9kap5ENmJ3TDVESHN0SCZlQXJDc2BDOIlmNxxUY0RkN2" ascii
      $s14 = "FzUZxWejZWMmV2ZpdjTxg3arMnQCB1LvoXY4kVdkFEeM1GcwB3TDllMFZGeTF3Z4MzRSR2KTBFaz8EWzBlQlJ0ckNHTpd2KwkURpBXQWF1ZjRTRqlVNvImYmF0bmtUYV" ascii
      $s15 = "NnW3oHNkZ3NY9mMTtmbNJTQx8WdNl3NCtCZGpVOMdUT2BzUWFTW5UjZu9CRIdHcLJzNoZTThhkVwgDOGdXM2B1dLlzUI9SQrllTqVkbst0TywmUwcXTPJmRvFFTPhEeh" ascii
      $s16 = "JUbL5WZxMXQux2bMNFNHhkVh1mY59UQP50Kp52N2FHa1ZHexcXN1oHRMhkes9icpZXU0VTc050VGZDOidUMPZDW0NkNwNjWxVHNrUUVvJmQ4p1LY10ZyFHTBBXcIZ2aZ" ascii
      $s17 = "FmN44kQz9yMRZTQKp1UmVFaOdnSSR3THdkSHJDdO5WRT90SSpHZjZVT3NUZwFkWWhlNpJzN04UZpRzLERnTtVGM4JTbyFGeTRXUwgHeyEmWTVlUr8kU4tyL2JnNTZENv" ascii
      $s18 = "d0aZ1WOFp1YTRWZ4tUVrN0Q5AVQEV3a3UnV2U0QkR3L3hEU3o3LJFWQnZzdzEUO4hFbBJDTUJGeopkclNjMFJDZ6lHa4o1LUVGShp0cup3L5dWZxpmS11mcix2VV5ERv" ascii
      $s19 = "9CNqJmSVRUZjFDR3B1VGhUNZNkQxNmS18WRwpHc2lUYBN1RYNXcntEZWNFeyEzMiRWQr8WOLRVZyg0QiF0QI1Gbr0mZvkmdyxUb4p3Kph2dadGb5EjSRFFdq9WSutydi" ascii
      $s20 = "dUb2JDZLdVVvpFe2YVS1lzSvl1MnlGdv92KKZWdWZGahxUaipGWypUeEZ3dyZWONJFTUdjTx5GR4p0KwYXaSZ2dLl2cRxGS4ZWdZFTNvoEeQpWRKJWQahkaTZWcz9iNa" ascii
   condition:
      uint16(0) == 0x6224 and filesize < 10000KB and
      1 of ($x*) and 4 of them
}

rule lazagne_ls_11462 {
   meta:
      description = "lazagne - file ls.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-05-01"
      hash1 = "8764131983eac23033c460833de5e439a4c475ad94cfd561d80cb62f86ff50a4"
   strings:
      $s1 = "pypykatz.lsadecryptor.packages.msv.templates(" fullword ascii
      $s2 = "pypykatz.lsadecryptor.packages.ssp.templates(" fullword ascii
      $s3 = "pypykatz.lsadecryptor.packages.kerberos.templates(" fullword ascii
      $s4 = "Failed to get address for PyImport_ExecCodeModule" fullword ascii
      $s5 = "pypykatz.commons.readers.local.common.kernel32(" fullword ascii
      $s6 = "pypykatz.lsadecryptor.packages.dpapi.templates(" fullword ascii
      $s7 = "pypykatz.lsadecryptor.packages.credman.templates(" fullword ascii
      $s8 = "pypykatz.lsadecryptor.packages.livessp.templates(" fullword ascii
      $s9 = "pypykatz.lsadecryptor.packages.wdigest.templates(" fullword ascii
      $s10 = "pypykatz.lsadecryptor.packages.tspkg.templates(" fullword ascii
      $s11 = "pypykatz.lsadecryptor.lsa_templates(" fullword ascii
      $s12 = "lazagne.config.lib.memorpy.SunProcess(" fullword ascii
      $s13 = "lazagne.config.lib.memorpy.BaseProcess(" fullword ascii
      $s14 = "lazagne.config.lib.memorpy.OSXProcess(" fullword ascii
      $s15 = "lazagne.config.lib.memorpy.Process(" fullword ascii
      $s16 = "lazagne.config.lib.memorpy.WinProcess(" fullword ascii
      $s17 = "lazagne.config.lib.memorpy.LinProcess(" fullword ascii
      $s18 = "lazagne.config.execute_cmd(" fullword ascii
      $s19 = "pypykatz.commons.readers.local.common.version(" fullword ascii
      $s20 = "pypykatz.commons.readers.local.common.privileges(" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 23000KB and
      ( pe.imphash() == "a62ff465f3ead2e578f02d3a2d749b7b" or 8 of them )
}

rule powershell_dll{
   meta:
      description = "11462 - powershell.dll"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com"
      date = "2022-03-22"
      hash1 = "2fcd6a4fd1215facea1fe1a503953e79b7a1cedc4d4320e6ab12461eb45dde30"
   strings:
      $s1 = "powershell.dll" fullword wide
      $s2 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii
      $s3 = "DynamicDllLoader" fullword ascii
      $s4 = "GetModuleCount" fullword ascii
      $s5 = "fnDllEntry" fullword ascii
      $s6 = "oldHeaders" fullword ascii
      $s7 = "dosHeader" fullword ascii
      $s8 = "IMAGE_EXPORT_DIRECTORY" fullword ascii
      $s9 = "Win32Imports" fullword ascii
      $s10 = "IMAGE_IMPORT_BY_NAME" fullword ascii
      $s11 = "BuildImportTable" fullword ascii
      $s12 = "MEMORYMODULE" fullword ascii
      $s13 = "lpAddress" fullword ascii /* Goodware String - occured 17 times */
      $s14 = "CurrentUser" fullword ascii /* Goodware String - occured 204 times */
      $s15 = "Signature" fullword ascii /* Goodware String - occured 282 times */
      $s16 = "Install" fullword wide /* Goodware String - occured 325 times */
      $s17 = "module" fullword ascii /* Goodware String - occured 467 times */
      $s18 = "Console" fullword ascii /* Goodware String - occured 526 times */
      $s19 = "EndInvoke" fullword ascii /* Goodware String - occured 915 times */
      $s20 = "BeginInvoke" fullword ascii /* Goodware String - occured 932 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      10 of them
}
