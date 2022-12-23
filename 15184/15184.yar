/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2022-11-28
   Identifier: Quantum Ransomware - Case 15184
   Reference: https://thedfirreport.com/2022/11/28/emotet-strikes-again-lnk-file-leads-to-domain-wide-ransomware/
*/

/* Rule Set ----------------------------------------------------------------- */

rule case_15184_FilesToHash_17jun {
   meta:
      description = "15184_ - file 17jun.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2022/11/28/emotet-strikes-again-lnk-file-leads-to-domain-wide-ransomware/"
      date = "2022-11-28"
      hash1 = "41e230134deca492704401ddf556ee2198ef6f32b868ec626d9aefbf268ab6b1"
   strings:
      $x1 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWCreateProcessAsUserWCryptAcq" ascii
      $x2 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125ERROR: unable to download agent fromGo pointer stored in" ascii
      $x3 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETCent" ascii
      $x4 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii
      $x5 = "VirtualQuery for stack base failedadding nil Certificate to CertPoolbad scalar length: %d, expected %dchacha20: wrong HChaCha20 " ascii
      $x6 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii
      $x7 = "tls: certificate used with invalid signature algorithmtls: server resumed a session with a different versionx509: cannot verify " ascii
      $x8 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=proxy-connectionreflect mismatchremote I/O errorruntime:  g:  g=" ascii
      $x9 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnablestrict-trans" ascii
      $x10 = "unixpacketunknown pcuser-agentws2_32.dll  of size   (targetpc= ErrCode=%v KiB work,  freeindex= gcwaiting= idleprocs= in status " ascii
      $x11 = "100-continue152587890625762939453125Bidi_ControlCIDR addressCONTINUATIONContent TypeContent-TypeCookie.ValueECDSA-SHA256ECDSA-SH" ascii
      $x12 = "entersyscallexit status gcBitsArenasgcpacertracegetaddrinfowhost is downhttp2debug=1http2debug=2illegal seekinvalid baseinvalid " ascii
      $x13 = "streamSafe was not resetstructure needs cleaningtext/html; charset=utf-8unexpected buffer len=%vx509: malformed validityzlib: in" ascii
      $x14 = "IP addressInstaller:Keep-AliveKharoshthiLockFileExManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCO" ascii
      $x15 = " to non-Go memory , locked to thread298023223876953125: day out of rangeArab Standard TimeCaucasian_AlbanianCommandLineToArgvWCr" ascii
      $x16 = "= flushGen  for type  gfreecnt= pages at  runqsize= runqueue= s.base()= spinning= stopwait= stream=%d sweepgen  sweepgen= target" ascii
      $x17 = "(unknown), newval=, oldval=, plugin:, size = , tail = --site-id244140625: status=AuthorityBassa_VahBhaiksukiClassINETCuneiformDi" ascii
      $x18 = " is unavailable()<>@,;:\\\"/[]?=,M3.2.0,M11.1.00601021504Z0700476837158203125: cannot parse <invalid Value>ASCII_Hex_DigitAccept" ascii
      $x19 = "span set block with unpopped elements found in resettls: received a session ticket with invalid lifetimetls: server selected uns" ascii
      $x20 = "bad defer entry in panicbad defer size class: i=bypassed recovery failedcan't scan our own stackcertificate unobtainablechacha20" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and
      1 of ($x*)
}

rule case_15184_dontsleep {
   meta:
      description = "15184_ - file dontsleep.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2022/11/28/emotet-strikes-again-lnk-file-leads-to-domain-wide-ransomware/"
      date = "2022-11-28"
      hash1 = "f8cff7082a936912baf2124d42ed82403c75c87cb160553a7df862f8d81809ee"
   strings:
      $s1 = "shell32.dll,Control_RunDLL" fullword ascii
      $s2 = "powrprof.DLL" fullword wide
      $s3 = "CREATEPROCESS_MANIFEST_RESOURCE_ID RT_MANIFEST \"res\\\\APP.exe.manifest\"" fullword ascii
      $s4 = "msinfo32.exe" fullword ascii
      $s5 = "user32.dll,LockWorkStation" fullword wide
      $s6 = "DontSleep.exe" fullword wide
      $s7 = "UMServer.log" fullword ascii
      $s8 = "_Autoupdate.exe" fullword ascii
      $s9 = "BlockbyExecutionState: %d on:%d by_enable:%d" fullword wide
      $s10 = "powrprof.dll,SetSuspendState" fullword wide
      $s11 = "%UserProfile%" fullword wide
      $s12 = " 2010-2019 Nenad Hrg SoftwareOK.com" fullword wide
      $s13 = "https://sectigo.com/CPS0C" fullword ascii
      $s14 = "https://sectigo.com/CPS0D" fullword ascii
      $s15 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii
      $s16 = "Unable to get response from Accept Thread withing specified Timeout ->" fullword ascii
      $s17 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii
      $s18 = "Unable to get response from Helper Thread within specified Timeout ->" fullword ascii
      $s19 = "   <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\">" fullword ascii
      $s20 = "_selfdestruct.bat" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule case_15184_FilesToHash_locker {
   meta:
      description = "15184_ - file locker.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2022/11/28/emotet-strikes-again-lnk-file-leads-to-domain-wide-ransomware/"
      date = "2022-11-28"
      hash1 = "6424b4983f83f477a5da846a1dc3e2565b7a7d88ae3f084f3d3884c43aec5df6"
   strings:
      $s1 = "plugin.dll" fullword ascii
      $s2 = "oL$0fE" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "H9CPtgL9{@tafD9{8tZD" fullword ascii
      $s4 = "expand 32-byte k" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "oD$@fD" fullword ascii /* Goodware String - occured 3 times */
      $s6 = "oF D3f0D3n4D3v8D3~<H" fullword ascii
      $s7 = "j]{7r]Y" fullword ascii
      $s8 = "EA>EmA" fullword ascii
      $s9 = "ol$0fE" fullword ascii
      $s10 = "S{L1I{" fullword ascii
      $s11 = "V32D!RT" fullword ascii
      $s12 = " A_A^_" fullword ascii
      $s13 = "v`L4~`g" fullword ascii
      $s14 = "9\\$8vsH" fullword ascii
      $s15 = "K:_Rich" fullword ascii
      $s16 = " A_A^A\\_^" fullword ascii
      $s17 = "tsf90u" fullword ascii
      $s18 = "9|$0vQ" fullword ascii
      $s19 = "K:_=:?^" fullword ascii
      $s20 = ":9o 49" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule case_15184_K_1_06_13_2022_lnk {
   meta:
      description = "15184_ - file K-1 06.13.2022.lnk.lnk"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-11-28"
      hash1 = "1bf9314ae67ab791932c43e6c64103b1b572a88035447dae781bffd21a1187ad"
   strings:
      $x1 = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword ascii
      $s2 = "%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide
      $s3 = "<..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide
      $s4 = "-c \"&{'p8ArwZsj8ZO+Zy/dHPeI+siGhbaxtEhzwmd3zVObm9uG2CGKqz5m4AdzKWWzPmKrjJieG4O9';$BxQ='uYnIvc3RhdHMvUkppMnJRSTRRWHJXQ2ZnZG1pLyI" wide
      $s5 = "WindowsPowerShell" fullword wide
      $s6 = "black-dog" fullword ascii
      $s7 = "powershell.exe" fullword wide /* Goodware String - occured 3 times */
      $s8 = "S-1-5-21-1499925678-132529631-3571256938-1001" fullword wide
   condition:
      uint16(0) == 0x004c and filesize < 10KB and
      1 of ($x*) and all of them
}
