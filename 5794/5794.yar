/*
   YARA Rule Set
   Author: TheDFIRReport
   Date: 2021-11-29
   Identifier: Case 5794 CONTInuing the Bazar Ransomware Story
   Reference: https://thedfirreport.com/2021/11/29/continuing-the-bazar-ransomware-story/
*/

/* Rule Set ----------------------------------------------------------------- */

rule mal_host2_143 {
   meta:
      description = "mal - file 143.dll"
      author = "TheDFIRReport"
      date = "2021-11-29"
      hash1 = "6f844a6e903aa8e305e88ac0f60328c184f71a4bfbe93124981d6a4308b14610"
   strings:
      $x1 = "object is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=" ascii
      $x2 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii
      $x3 = " to unallocated spanCertOpenSystemStoreWCreateProcessAsUserWCryptAcquireContextWGetAcceptExSockaddrsGetCurrentDirectoryWGetFileA" ascii
      $x4 = "Go pointer stored into non-Go memoryUnable to determine system directoryaccessing a corrupted shared libraryruntime: VirtualQuer" ascii
      $x5 = "GetAddrInfoWGetLastErrorGetLengthSidGetStdHandleGetTempPathWLoadLibraryWReadConsoleWSetEndOfFileTransmitFileabi mismatchadvapi32" ascii
      $x6 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii
      $x7 = "unknown pcws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= heap_live= idleprocs= in status  mallocing= ms clock" ascii
      $x8 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii
      $x9 = ".lib section in a.out corruptedbad write barrier buffer boundscall from within the Go runtimecannot assign requested addresscasg" ascii
      $x10 = "Ptrmask.lockentersyscallblockexec format errorg already scannedglobalAlloc.mutexlocked m0 woke upmark - bad statusmarkBits overf" ascii
      $x11 = "entersyscallgcBitsArenasgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdontneedmheapSpe" ascii
      $x12 = "ollectionidentifier removedindex out of rangeinput/output errormultihop attemptedno child processesno locks availableoperation c" ascii
      $s13 = "y failed; errno=runtime: bad notifyList size - sync=runtime: invalid pc-encoded table f=runtime: invalid typeBitsBulkBarrierrunt" ascii
      $s14 = "ddetailsecur32.dllshell32.dlltracealloc(unreachableuserenv.dll KiB total,  [recovered] allocCount  found at *( gcscandone  m->gs" ascii
      $s15 = ".dllbad flushGenbad g statusbad g0 stackbad recoverycan't happencas64 failedchan receivedumping heapend tracegc" fullword ascii
      $s16 = "ked to threadCommandLineToArgvWCreateFileMappingWGetExitCodeProcessGetFileAttributesWLookupAccountNameWRFS specific errorSetFile" ascii
      $s17 = "mstartbad sequence numberdevice not a streamdirectory not emptydisk quota exceededdodeltimer: wrong Pfile already closedfile alr" ascii
      $s18 = "structure needs cleaning bytes failed with errno= to unused region of spanGODEBUG: can not enable \"GetQueuedCompletionStatus_cg" ascii
      $s19 = "garbage collection scangcDrain phase incorrectindex out of range [%x]interrupted system callinvalid m->lockedInt = left over mar" ascii
      $s20 = "tProcessIdGetSystemDirectoryWGetTokenInformationWaitForSingleObjectadjusttimers: bad pbad file descriptorbad notifyList sizebad " ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 12 of them
}

rule mal_host1_D8B3 {
   meta:
      description = "mal - file D8B3.dll"
      author = "TheDFIRReport"
      date = "2021-11-29"
      hash1 = "4a49cf7539f9fd5cc066dc493bf16598a38a75f7b656224db1ddd33005ad76f6"
   strings:
      $x1 = "object is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=" ascii
      $x2 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii
      $x3 = " to unallocated spanCertOpenSystemStoreWCreateProcessAsUserWCryptAcquireContextWGetAcceptExSockaddrsGetCurrentDirectoryWGetFileA" ascii
      $x4 = "Go pointer stored into non-Go memoryUnable to determine system directoryaccessing a corrupted shared libraryruntime: VirtualQuer" ascii
      $x5 = "GetAddrInfoWGetLastErrorGetLengthSidGetStdHandleGetTempPathWLoadLibraryWReadConsoleWSetEndOfFileTransmitFileabi mismatchadvapi32" ascii
      $x6 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii
      $x7 = "unknown pcws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= heap_live= idleprocs= in status  mallocing= ms clock" ascii
      $x8 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii
      $x9 = ".lib section in a.out corruptedbad write barrier buffer boundscall from within the Go runtimecannot assign requested addresscasg" ascii
      $x10 = "Ptrmask.lockentersyscallblockexec format errorg already scannedglobalAlloc.mutexlocked m0 woke upmark - bad statusmarkBits overf" ascii
      $x11 = "entersyscallgcBitsArenasgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdontneedmheapSpe" ascii
      $x12 = "ollectionidentifier removedindex out of rangeinput/output errormultihop attemptedno child processesno locks availableoperation c" ascii
      $s13 = "y failed; errno=runtime: bad notifyList size - sync=runtime: invalid pc-encoded table f=runtime: invalid typeBitsBulkBarrierrunt" ascii
      $s14 = "ddetailsecur32.dllshell32.dlltracealloc(unreachableuserenv.dll KiB total,  [recovered] allocCount  found at *( gcscandone  m->gs" ascii
      $s15 = ".dllbad flushGenbad g statusbad g0 stackbad recoverycan't happencas64 failedchan receivedumping heapend tracegc" fullword ascii
      $s16 = "ked to threadCommandLineToArgvWCreateFileMappingWGetExitCodeProcessGetFileAttributesWLookupAccountNameWRFS specific errorSetFile" ascii
      $s17 = "mstartbad sequence numberdevice not a streamdirectory not emptydisk quota exceededdodeltimer: wrong Pfile already closedfile alr" ascii
      $s18 = "structure needs cleaning bytes failed with errno= to unused region of spanGODEBUG: can not enable \"GetQueuedCompletionStatus_cg" ascii
      $s19 = "garbage collection scangcDrain phase incorrectindex out of range [%x]interrupted system callinvalid m->lockedInt = left over mar" ascii
      $s20 = "tProcessIdGetSystemDirectoryWGetTokenInformationWaitForSingleObjectadjusttimers: bad pbad file descriptorbad notifyList sizebad " ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and all of them
}


rule mal_host2_AnyDesk {
   meta:
      description = "mal - file AnyDesk.exe"
      author = "TheDFIRReport"
      date = "2021-11-29"
      hash1 = "8f09c538fc587b882eecd9cfb869c363581c2c646d8c32a2f7c1ff3763dcb4e7"
   strings:
      $x1 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" pu" ascii
      $x2 = "C:\\Buildbot\\ad-windows-32\\build\\release\\app-32\\win_loader\\AnyDesk.pdb" fullword ascii
      $s3 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" pu" ascii
      $s4 = "<assemblyIdentity version=\"6.3.2.0\" processorArchitecture=\"x86\" name=\"AnyDesk.AnyDesk.AnyDesk\" type=\"win32\" />" fullword ascii
      $s5 = "4http://crl3.digicert.com/DigiCertAssuredIDRootCA.crl0O" fullword ascii
      $s6 = "(Symantec SHA256 TimeStamping Signer - G3" fullword ascii
      $s7 = "(Symantec SHA256 TimeStamping Signer - G30" fullword ascii
      $s8 = "http://ocsp.digicert.com0N" fullword ascii
      $s9 = "http://www.digicert.com/CPS0" fullword ascii
      $s10 = "Bhttp://cacerts.digicert.com/DigiCertSHA2AssuredIDCodeSigningCA.crt0" fullword ascii
      $s11 = "<description>AnyDesk screen sharing and remote control software.</description>" fullword ascii
      $s12 = "/http://crl3.digicert.com/sha2-assured-cs-g1.crl05" fullword ascii
      $s13 = "/http://crl4.digicert.com/sha2-assured-cs-g1.crl0L" fullword ascii
      $s14 = "%jgmRhZl%" fullword ascii
      $s15 = "5ZW:\"Wfh" fullword ascii
      $s16 = "5HRe:\\" fullword ascii
      $s17 = "ysN.JTf" fullword ascii
      $s18 = "Z72.irZ" fullword ascii
      $s19 = "Ve:\\-Sj7" fullword ascii
      $s20 = "ekX.cFm" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      1 of ($x*) and 4 of them
}

rule ProcessHacker {
   meta:
      description = "mal - file ProcessHacker.exe"
      author = "TheDFIRReport"
      date = "2021-11-29"
      hash1 = "d4a0fe56316a2c45b9ba9ac1005363309a3edc7acf9e4df64d326a0ff273e80f"
   strings:
      $x1 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskmgr.exe" fullword wide
      $x2 = "D:\\Projects\\processhacker2\\bin\\Release32\\ProcessHacker.pdb" fullword ascii
      $x3 = "ProcessHacker.exe" fullword wide
      $x4 = "kprocesshacker.sys" fullword wide
      $x5 = "ntdll.dll!NtDelayExecution" fullword wide
      $x6 = "ntdll.dll!ZwDelayExecution" fullword wide
      $s7 = "PhInjectDllProcess" fullword ascii
      $s8 = "_PhUiInjectDllProcess@8" fullword ascii
      $s9 = "logonui.exe" fullword wide
      $s10 = "Executable files (*.exe;*.dll;*.ocx;*.sys;*.scr;*.cpl)" fullword wide
      $s11 = "\\x86\\ProcessHacker.exe" fullword wide
      $s12 = "user32.dll!NtUserGetMessage" fullword wide
      $s13 = "ntdll.dll!NtWaitForKeyedEvent" fullword wide
      $s14 = "ntdll.dll!ZwWaitForKeyedEvent" fullword wide
      $s15 = "ntdll.dll!NtReleaseKeyedEvent" fullword wide
      $s16 = "ntdll.dll!ZwReleaseKeyedEvent" fullword wide
      $s17 = "\\kprocesshacker.sys" fullword wide
      $s18 = "\\SystemRoot\\system32\\drivers\\ntfs.sys" fullword wide
      $s19 = "_PhExecuteRunAsCommand2@36" fullword ascii
      $s20 = "_PhShellExecuteUserString@20" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule unlocker {
   meta:
      description = "mal - file unlocker.exe"
      author = "TheDFIRReport"
      date = "2021-11-29"
      hash1 = "09d7fcbf95e66b242ff5d7bc76e4d2c912462c8c344cb2b90070a38d27aaef53"
   strings:
      $s1 = "For more detailed information, please visit http://www.jrsoftware.org/ishelp/index.php?topic=setupcmdline" fullword wide
      $s2 = "(Symantec SHA256 TimeStamping Signer - G20" fullword ascii
      $s3 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>" fullword ascii
      $s4 = "(Symantec SHA256 TimeStamping Signer - G2" fullword ascii
      $s5 = "Causes Setup to create a log file in the user's TEMP directory." fullword wide
      $s6 = "Prevents the user from cancelling during the installation process." fullword wide
      $s7 = "Same as /LOG, except it allows you to specify a fixed path/filename to use for the log file." fullword wide
      $s8 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii
      $s9 = "The Setup program accepts optional command line parameters." fullword wide
      $s10 = "Instructs Setup to load the settings from the specified file after having checked the command line." fullword wide
      $s11 = "Overrides the default component settings." fullword wide
      $s12 = "/MERGETASKS=\"comma separated list of task names\"" fullword wide
      $s13 = "/PASSWORD=password" fullword wide
      $s14 = "Specifies the password to use." fullword wide
      $s15 = "yyyyvvvvvvvvvxxw" fullword ascii
      $s16 = "yyyyyyrrrsy" fullword ascii
      $s17 = "            processorArchitecture=\"x86\"" fullword ascii
      $s18 = "    processorArchitecture=\"x86\"" fullword ascii
      $s19 = "Prevents Setup from restarting the system following a successful installation, or after a Preparing to Install failure that requ" wide
      $s20 = "/DIR=\"x:\\dirname\"" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule mal_host2_locker {
   meta:
      description = "mal - file locker.bat"
      author = "TheDFIRReport"
      date = "2021-11-29"
      hash1 = "1edfae602f195d53b63707fe117e9c47e1925722533be43909a5d594e1ef63d3"
   strings:
      $x1 = "_locker.exe -m -net -size 10 -nomutex -p" ascii
   condition:
      uint16(0) == 0x7473 and filesize < 8KB and
      $x1
}

import "pe"

rule o4IRWsH4N1a3hjO9Sy2rPP02oyUddH7zA5xGih0ESmlhiiXD9kpWVCPfOwUnayZp_locker {
   meta:
      description = "conti - file o4IRWsH4N1a3hjO9Sy2rPP02oyUddH7zA5xGih0ESmlhiiXD9kpWVCPfOwUnayZp_locker.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2021-11-29"
      hash1 = "9cd3c0cff6f3ecb31c7d6bc531395ccfd374bcd257c3c463ac528703ae2b0219"
   strings:
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s2 = "operator co_await" fullword ascii
      $s3 = ">*>6>A>_>" fullword ascii /* hex encoded string 'j' */
      $s4 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s5 = "Bapi-ms-win-core-fibers-l1-1-1" fullword wide
      $s6 = "SVWjEhQ" fullword ascii
      $s7 = ";F;[;l;" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "74787@7H7P7T7\\7p7" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "6#606B6" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "<!=X=u=" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "expand 32-byte k" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "6!7?7J7" fullword ascii /* Goodware String - occured 2 times */
      $s13 = "delete" fullword ascii /* Goodware String - occured 2789 times */
      $s14 = "4!4(4/464=4D4K4R4Z4b4j4v4" fullword ascii /* Goodware String - occured 3 times */
      $s15 = ".CRT$XIAC" fullword ascii /* Goodware String - occured 3 times */
      $s16 = "0#0)01060\\0a0" fullword ascii
      $s17 = ";\";/;=;K;V;l;" fullword ascii
      $s18 = "6,606P6X6\\6x6" fullword ascii
      $s19 = "6(6,6@6D6H6L6P6T6X6\\6`6d6p6t6x6|6" fullword ascii
      $s20 = "8 :M:}:" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      ( pe.imphash() == "50472e0ba953856d228c7483b149ea72" or all of them )
}

rule o4IRWsH4N1a3hjO9Sy2rPP02oyUddH7zA5xGih0ESmlhiiXD9kpWVCPfOwUnayZp_locker_x86 {
   meta:
      description = "conti - file o4IRWsH4N1a3hjO9Sy2rPP02oyUddH7zA5xGih0ESmlhiiXD9kpWVCPfOwUnayZp_locker_x86.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2021-11-29"
      hash1 = "01a9549c015cfcbff4a830cea7df6386dc5474fd433f15a6944b834551a2b4c9"
   strings:
      $s1 = "conti_v3.dll" fullword ascii
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s3 = "6 7/787E7[7" fullword ascii /* hex encoded string 'gx~w' */
      $s4 = "operator co_await" fullword ascii
      $s5 = "2%3.3f3~3" fullword ascii /* hex encoded string '#?3' */
      $s6 = "1\"1&1,:4:<:D:L:T:\\:d:l:t:|:" fullword ascii $s7 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide $s8 = "SVWjEhQ" fullword ascii $s9 = "__swift_2" fullword ascii $s10 = "__swift_1" fullword ascii $s11 = "api-ms-win-core-file-l1-2-2" fullword wide /* Goodware String - occured 1 times */ $s12 = "7K7P7T7X7\\7" fullword ascii /* Goodware String - occured 1 times */ $s13 = "7h7o7v7}7" fullword ascii /* Goodware String - occured 1 times */ $s14 = "O0a0s0" fullword ascii /* Goodware String - occured 1 times */ $s15 = ";?;I;S;" fullword ascii /* Goodware String - occured 1 times */ $s16 = "8>8C8Q8V8" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "QQSVj8j@" fullword ascii
      $s18 = "5-5X5s5" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "expand 32-byte k" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "delete" fullword ascii /* Goodware String - occured 2789 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      ( pe.imphash() == "749dc5143e9fc01aa1d221fb9a48d5ea" or all of them )
}

rule o4IRWsH4N1a3hjO9Sy2rPP02oyUddH7zA5xGih0ESmlhiiXD9kpWVCPfOwUnayZp_locker_x64 {
   meta:
      description = "conti - file o4IRWsH4N1a3hjO9Sy2rPP02oyUddH7zA5xGih0ESmlhiiXD9kpWVCPfOwUnayZp_locker_x64.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2021-11-29"
      hash1 = "31656dcea4da01879e80dff59a1af60ca09c951fe5fc7e291be611c4eadd932a"
   strings:
      $s1 = "conti_v3.dll" fullword ascii
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s3 = "operator co_await" fullword ascii
      $s4 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s5 = "api-ms-win-core-file-l1-2-2" fullword wide /* Goodware String - occured 1 times */
      $s6 = "__swift_2" fullword ascii
      $s7 = "__swift_1" fullword ascii
      $s8 = "expand 32-byte k" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "u3HcH<H" fullword ascii /* Goodware String - occured 2 times */
      $s10 = "D$XD9x" fullword ascii /* Goodware String - occured 2 times */
      $s11 = "delete" fullword ascii /* Goodware String - occured 2789 times */
      $s12 = "ue!T$(H!T$ " fullword ascii
      $s13 = "L$&8\\$&t,8Y" fullword ascii
      $s14 = "F 2-by" fullword ascii
      $s15 = "u\"8Z(t" fullword ascii
      $s16 = "L$ |+L;" fullword ascii
      $s17 = "vB8_(t" fullword ascii
      $s18 = "ext-ms-" fullword wide
      $s19 = "OOxq*H" fullword ascii
      $s20 = "H97u+A" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      ( pe.imphash() == "137fa89046164fe07e0dd776ed7a0191" or all of them )
}
