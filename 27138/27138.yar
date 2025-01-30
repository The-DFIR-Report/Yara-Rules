/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2025-01-23
   Identifier: Case 27138
   Reference: https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule sig_27138_Veeam_Get_Creds {
   meta:
      description = "27138 - file Veeam-Get-Creds.ps1"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/"
      date = "2025-01-23"
      hash1 = "18051333e658c4816ff3576a2e9d97fe2a1196ac0ea5ed9ba386c46defafdb88"
   strings:
      $x1 = "# Usage:  Run as administrator (elevated) in PowerShell on a host in a Veeam " fullword ascii
      $s2 = "$SqlDatabaseName = (Get-ItemProperty -Path $VeaamRegPath -ErrorAction Stop).SqlDatabaseName " fullword ascii
      $s3 = "$SqlServerName = (Get-ItemProperty -Path $VeaamRegPath -ErrorAction Stop).SqlServerName" fullword ascii
      $s4 = "$SqlInstanceName = (Get-ItemProperty -Path $VeaamRegPath -ErrorAction Stop).SqlInstanceName" fullword ascii
      $s5 = "$command = New-Object System.Data.OleDb.OleDbCommand $SQL, $connection" fullword ascii
      $s6 = "# About:  The script is designed to recover passwords used by Veeam to connect" fullword ascii
      $s7 = "$rows | ForEach-Object -Process {" fullword ascii
      $s8 = "$adapter = New-Object System.Data.OleDb.OleDbDataAdapter $command" fullword ascii
      $s9 = "\"Here are some passwords for you, have fun:\"" fullword ascii
      $s10 = "$SQL = \"SELECT [user_name] AS 'User name',[password] AS 'Password' FROM [$SqlDatabaseName].[dbo].[Credentials] \"+" fullword ascii
      $s11 = "$_.password = $enc.GetString($ClearPWD)" fullword ascii
      $s12 = "#         to remote hosts vSphere, Hyper-V, etc. The script is intended for " fullword ascii
      $s13 = "$EnryptedPWD = [Convert]::FromBase64String($_.password)" fullword ascii
      $s14 = "#Decrypting passwords using DPAPI" fullword ascii
      $s15 = "#Fetching encrypted credentials from the database" fullword ascii
      $s16 = "$connection = New-Object System.Data.OleDb.OleDbConnection $connectionString" fullword ascii
      $s17 = "\"No passwords today, sorry.\"" fullword ascii
      $s18 = "\"WHERE password <> ''\" #Filter empty passwords" fullword ascii
      $s19 = "# Author: Konstantin Burov." fullword ascii
      $s20 = "echo \"Can't find Veeam on localhost, try running as Administrator\"" fullword ascii
   condition:
      uint16(0) == 0x2023 and filesize < 7KB and
      1 of ($x*) and 4 of them
}

rule sig_27138_lockbit_sd {
   meta:
      description = "27138 - file sd.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/"
      date = "2025-01-23"
      hash1 = "c1173628f18f7430d792bbbefc6878bced4539c8080d518555d08683a3f1a835"
   strings:
      $s1 = "< /s|V" fullword ascii
      $s2 = "7- h^O" fullword ascii
      $s3 = "NBWg|?G" fullword ascii
      $s4 = "}xcVW*&%%" fullword ascii
      $s5 = "joCw}sP" fullword ascii
      $s6 = "oVHpT0S" fullword ascii
      $s7 = "ngMVj;#<d" fullword ascii
      $s8 = "PNaWt'." fullword ascii
      $s9 = "JMBQWb=\\" fullword ascii
      $s10 = "37TsYA?" fullword ascii
      $s11 = "mSLYP&`d" fullword ascii
      $s12 = "UkqZ3mg" fullword ascii
      $s13 = "jQeP]q-W" fullword ascii
      $s14 = "ikhN=Z\\f" fullword ascii
      $s15 = "MOnt`#$z" fullword ascii
      $s16 = "qtkw[,4" fullword ascii
      $s17 = "rKc4[yNent+#" fullword ascii
      $s18 = "GuiA3\"" fullword ascii
      $s19 = "kAJK}C%^" fullword ascii
      $s20 = "_.gQA[ZIc" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      ( pe.imphash() == "89b43582b27abefb2b74684ab12a2f8e" or 8 of them )
}


rule sig_27138_setup_wm {
   meta:
      description = "27138 - file setup_wm.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/"
      date = "2025-01-23"
      hash1 = "d8b2d883d3b376833fa8e2093e82d0a118ba13b01a2054f8447f57d9fec67030"
   strings:
      $s1 = "##### Service XML download Complete" fullword ascii
      $s2 = "http://go.microsoft.com/fwlink/?LinkId=120764&mpver=%s&id=%x&contextid=%lu&originalid=%lu" fullword wide
      $s3 = "http://go.microsoft.com/fwlink/?LinkId=120764&mpver=%s&id=%x&contextid=%lu&originalid=%x" fullword wide
      $s4 = "Title=res://wmploc.dll/RT_STRING/#1700;Author=res://wmploc.dll/RT_STRING/#1701;MediaType=res://wmploc.dll/RT_STRING/#1715;FileTy" wide
      $s5 = " /NoMutex /Quiet" fullword wide
      $s6 = "6666666666%" fullword ascii /* reversed goodware string '%6666666666' */ /* hex encoded string 'fffff' */
      $s7 = "ERROR: Execution of %S failed. Setup will not fail because of this issue." fullword ascii
      $s8 = "5556666666" ascii /* hex encoded string 'UVfff' */
      $s9 = "33333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333" ascii /* hex encoded string '333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333' */
      $s10 = "66666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666" ascii /* hex encoded string 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' */
      $s11 = "55555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555" ascii /* hex encoded string 'UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU' */
      $s12 = "333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333" ascii /* hex encoded string '333333333333333333333333333333333333333333333333333333333333' */
      $s13 = "777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777" ascii /* hex encoded string 'wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww' */
      $s14 = "222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222" ascii /* hex encoded string '""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""' */
      $s15 = "6666666665" ascii /* hex encoded string 'ffffe' */
      $s16 = "555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555" ascii /* hex encoded string 'UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU' */
      $s17 = "2222333333333333" ascii /* hex encoded string '""333333' */
      $s18 = "44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444" ascii /* hex encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' */
      $s19 = "4455555666" ascii /* hex encoded string 'DUUVf' */
      $s20 = "666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666" ascii /* hex encoded string 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' */
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      ( pe.imphash() == "914f48205872e2a197aaae4775f619b3" or all of them )
}


rule sig_27138_share_svcmc {
   meta:
      description = "27138 - file svcmc.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/"
      date = "2025-01-23"
      hash1 = "ced4ee8a9814c243f0c157cda900def172b95bb4bc8535e480fe432ab84b9175"
   strings:
      $x1 = "GoneDATAPING&lt;&gt;idle1080openStat.com.exe.bat.cmdquitallgallprootitabsbrk is LEAFbaseGOGC+Inf-Infcas1cas2cas3cas4cas5cas63125" ascii
      $x2 = "SsAinteger divide by zeroCountPagesInUse (test)ReadMetricsSlow (test)trace reader (blocked)send on closed channelgetenv before e" ascii
      $x3 = "goroutine profileAllThreadsSyscallGC assist markingselect (no cases)sync.RWMutex.Lockwait for GC cycle: missing method notetslee" ascii
      $x4 = "{runtime: unable to acquire - semaphore out of syncmallocgc called with gcphase == _GCmarkterminationrecursive call during initi" ascii
      $x5 = "alization - linker skewattempt to execute system stack code on user stackcompileCallback: function argument frame too large" fullword ascii
      $x6 = "read on pipeunixicmpigmpftpshttppop3smtpIdleOpenPOSTEtag0x%xdateetagfromhostlinkvarypathHostDategzip%x" fullword ascii
      $x7 = "free space/gc/scan/globals:bytes/gc/heap/frees:objectsscanstack - bad statusheadTailIndex overflowkernel32.dll not foundadvapi3" fullword ascii
      $x8 = "activeSweepmheap.freeSpanLocked - invalid freeattempt to clear non-empty span setruntime: close polldesc w/o unblockruntime: in" fullword ascii
      $s9 = "t] (types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeassignment to entry in nil map/cpu/c" ascii
      $s10 = "bad defer entry in panicbypassed recovery failedbindm in unexpected GOOSrunqsteal: runq overflowdouble traceGCSweepStartR\\" fullword ascii
      $s11 = "floating point errorGC sweep terminationResetDebugLog (test)chan send (nil chan)malloc during signalclose of nil channelnotetsle" ascii
      $s12 = "6runtime: typeBitsBulkBarrier without type/memory/classes/metadata/mspan/free:bytesruntime.SetFinalizer: second argument is gcSw" ascii
      $s13 = "eSpanLocked - invalid span stateattempted to add zero-sized address rangeruntime: blocked read on closing polldescstopTheWorld: " ascii
      $s14 = "mheap.freeSpanLocked - invalid free of user arena chunkcasfrom_Gscanstatus:top gp->status is not in scan state is currently not " ascii
      $s15 = "sweepWaiterstraceStringsspanSetSpinemspanSpecialgcBitsArenasmheapSpecialgcpacertracemadvdontneedharddecommitdumping heapchan rec" ascii
      $s16 = "sweepWaiterstraceStringsspanSetSpinemspanSpecialgcBitsArenasmheapSpecialgcpacertracemadvdontneedharddecommitdumping heapchan rec" ascii
      $s17 = "t] (types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeassignment to entry in nil map/cpu/c" ascii
      $s18 = "fumari.dll" fullword ascii
      $s19 = "persistentalloc: align is too large/memory/classes/heap/released:bytesgreyobject: obj not pointer-alignedmismatched begin/end of" ascii
      $s20 = "write heap dumpasyncpreemptoffforce gc (idle)sync.Mutex.Lockmalloc deadlockruntime error: scan missed a gmisaligned maskrecovery" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 24000KB and
      ( pe.imphash() == "5ece094e7f2f03efa6f8d51d9a698823" and ( pe.exports("MainFunc") and pe.exports("_cgo_dummy_export") ) or ( 1 of ($x*) or 4 of them ) )
}

rule sig_27138_systembc_svc {
   meta:
      description = "27138 - file svc.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/"
      date = "2025-01-23"
      hash1 = "2389b3978887ec1094b26b35e21e9c77826d91f7fa25b2a1cb5ad836ba2d7ec4"
   strings:
      $s1 = "socks64.dll" fullword ascii
      $s2 = "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0" fullword ascii
      $s3 = "FGET %s HTTP/1.0" fullword ascii
      $s4 = "rundll" fullword ascii
      $s5 = "SWVATAUAVAWH" fullword ascii
      $s6 = "SQWVATAUAVAWH" fullword ascii
      $s7 = "PSWVATAUAVAWH" fullword ascii
      $s8 = "XA_A^A]A\\^_[]" fullword ascii
      $s9 = "(A_A^A]A\\^_[]" fullword ascii
      $s10 = "8A_A^A]A\\^_[]" fullword ascii
      $s11 = "A_A^A]A\\^_[X]" fullword ascii
      $s12 = "A_A^A]A\\^_Y[]" fullword ascii
      $s13 = "A_A^A]A\\^_[]" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      ( pe.imphash() == "dbd4201cf48f9c38a17d30012392cf92" and pe.exports("rundll") or 8 of them )
}

rule sig_27138_svchosts_ghostsocks {
   meta:
      description = "27138 - file svchosts.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/"
      date = "2025-01-23"
      hash1 = "b4ad5df385ee964fe9a800f2cdaa03626c8e8811ddb171f8e821876373335e63"
   strings:
      $x1 = "GoneDATAPING&lt;&gt;idle1080openStat.com.exe.bat.cmdquitallgallprootitabsbrk is LEAFbaseGOGC+Inf-Infcas1cas2cas3cas4cas5cas63125" ascii
      $x2 = "integer divide by zeroCountPagesInUse (test)ReadMetricsSlow (test)trace reader (blocked)send on closed channelgetenv before env " ascii
      $x3 = "goroutine profileAllThreadsSyscallGC assist markingselect (no cases)sync.RWMutex.Lockwait for GC cycle: missing method notetslee" ascii
      $x4 = "runtime: unable to acquire - semaphore out of syncmallocgc called with gcphase == _GCmarkterminationrecursive call during initia" ascii
      $x5 = "lization - linker skewattempt to execute system stack code on user stackcompileCallback: function argument frame too largewq" fullword ascii
      $x6 = "read on pipeunixicmpigmpftpshttppop3smtpIdleOpenPOSTEtag0x%xdateetagfromhostlinkvarypathHostDategzip%x" fullword ascii
      $x7 = "ee space/gc/scan/globals:bytes/gc/heap/frees:objectsscanstack - bad statusheadTailIndex overflowkernel32.dll not foundadvapi32.d" ascii
      $x8 = "activeSweepmheap.freeSpanLocked - invalid freeattempt to clear non-empty span setruntime: close polldesc w/o unblockruntime: in" fullword ascii
      $s9 = "(types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeassignment to entry in nil map/cpu/clas" ascii
      $s10 = "bad defer entry in panicbypassed recovery failedbindm in unexpected GOOSrunqsteal: runq overflowdouble traceGCSweepStartY" fullword ascii
      $s11 = "floating point errorGC sweep terminationResetDebugLog (test)chan send (nil chan)malloc during signalclose of nil channelnotetsle" ascii
      $s12 = "9runtime: typeBitsBulkBarrier without type/memory/classes/metadata/mspan/free:bytesruntime.SetFinalizer: second argument is gcSw" ascii
      $s13 = "mheap.freeSpanLocked - invalid free of user arena chunkcasfrom_Gscanstatus:top gp->status is not in scan state is currently not " ascii
      $s14 = "eSpanLocked - invalid span stateattempted to add zero-sized address rangeruntime: blocked read on closing polldescstopTheWorld: " ascii
      $s15 = "sweepWaiterstraceStringsspanSetSpinemspanSpecialgcBitsArenasmheapSpecialgcpacertracemadvdontneedharddecommitdumping heapchan rec" ascii
      $s16 = "sweepWaiterstraceStringsspanSetSpinemspanSpecialgcBitsArenasmheapSpecialgcpacertracemadvdontneedharddecommitdumping heapchan rec" ascii
      $s17 = "(types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeassignment to entry in nil map/cpu/cla" fullword ascii
      $s18 = "persistentalloc: align is too large/memory/classes/heap/released:bytesgreyobject: obj not pointer-alignedmismatched begin/end of" ascii
      $s19 = "nSoyomboTagalogTibetanTirhutaRadicalSHA-224SHA-256SHA-384SHA-512os/execruntime#internDES-CBCEd25519MD2-RSAMD5-RSAserial:2.5.4.62" ascii
      $s20 = "3Wwrite heap dumpasyncpreemptoffforce gc (idle)sync.Mutex.Lockmalloc deadlockruntime error: scan missed a gmisaligned maskrecove" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 24000KB and
      ( pe.imphash() == "4f2f006e2ecf7172ad368f8289dc96c1" or ( 1 of ($x*) or 4 of them ) )
}

rule sig_27138_share__SETUP {
   meta:
      description = "27138 - file SETUP.bat"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/"
      date = "2025-01-23"
      hash1 = "7673a949181e33ff8ed77d992a2826c25b8da333f9e03213ae3a72bb4e9a705d"
   strings:
      $s1 = "net share share$=%cd% /GRANT:Everyone,READ /Y" fullword ascii
      $s2 = "if %errorLevel% == 0 (" fullword ascii
      $s3 = "echo ERROR! Please run this file as Administrator!" fullword ascii
      $s4 = "net session >nul 2>&1" fullword ascii
      $s5 = "echo Administrative permissions required." fullword ascii
      $s6 = "echo Success : Administrative permissions confirmed." fullword ascii
      $s7 = ") else (" fullword ascii
      $s8 = "cd %~dp0" fullword ascii
   condition:
      uint16(0) == 0x6540 and filesize < 1KB and
      all of them
}

rule sig_27138_files_check {
   meta:
      description = "27138 - file check.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/"
      date = "2025-01-23"
      hash1 = "3f97e112f0c5ddf0255ef461746a223208dc0846bde2a6dca9c825d9c706a4e9"
   strings:
      $x1 = "C:\\Users\\ad\\source\\repos\\ReadByte\\ReadByte\\obj\\Release\\DiskCheck.pdb" fullword ascii
      $s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s3 = "DiskCheck.exe" fullword wide
      $s4 = "computers.txt" fullword wide
      $s5 = "Error.txt" fullword wide
      $s6 = "SELECT * FROM Win32_LoggedOnUser" fullword wide
      $s7 = "Complete!!!" fullword wide
      $s8 = "LivePc.txt" fullword wide
      $s9 = "DeadPc.txt" fullword wide
      $s10 = "Success!!!" fullword wide
      $s11 = "vSphere!!!" fullword wide
      $s12 = "Synology" fullword wide
      $s13 = "Programs.csv" fullword wide
      $s14 = ".NETFramework,Version=v4.6.2" fullword ascii
      $s15 = ".NET Framework 4.6.2" fullword ascii
      $s16 = "ReadByte.Form1+<Disk>d__5" fullword ascii
      $s17 = "ReadRemoteRegistryusingWMI" fullword ascii
      $s18 = "diskSpace.csv" fullword wide
      $s19 = "ReadByte.Form1.resources" fullword ascii
      $s20 = "SELECT * FROM Win32_MappedLogicalDisk" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      1 of ($x*) and 4 of them
}




/* Super Rules ------------------------------------------------------------- */

rule sig_27138_svcmc_svchosts_0 {
   meta:
      description = "27138 - from files svcmc.dll, svchosts.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/"
      date = "2025-01-23"
      hash1 = "ced4ee8a9814c243f0c157cda900def172b95bb4bc8535e480fe432ab84b9175"
      hash2 = "b4ad5df385ee964fe9a800f2cdaa03626c8e8811ddb171f8e821876373335e63"
   strings:
      $x1 = "goroutine profileAllThreadsSyscallGC assist markingselect (no cases)sync.RWMutex.Lockwait for GC cycle: missing method notetslee" ascii
      $x2 = "read on pipeunixicmpigmpftpshttppop3smtpIdleOpenPOSTEtag0x%xdateetagfromhostlinkvarypathHostDategzip%x" fullword ascii
      $x3 = "activeSweepmheap.freeSpanLocked - invalid freeattempt to clear non-empty span setruntime: close polldesc w/o unblockruntime: in" fullword ascii
      $s4 = "eSpanLocked - invalid span stateattempted to add zero-sized address rangeruntime: blocked read on closing polldescstopTheWorld: " ascii
      $s5 = "sweepWaiterstraceStringsspanSetSpinemspanSpecialgcBitsArenasmheapSpecialgcpacertracemadvdontneedharddecommitdumping heapchan rec" ascii
      $s6 = "sweepWaiterstraceStringsspanSetSpinemspanSpecialgcBitsArenasmheapSpecialgcpacertracemadvdontneedharddecommitdumping heapchan rec" ascii
      $s7 = "persistentalloc: align is too large/memory/classes/heap/released:bytesgreyobject: obj not pointer-alignedmismatched begin/end of" ascii
      $s8 = "shedworkbuf is not emptybad use of bucket.mpbad use of bucket.bpruntime: double waitws2_32.dll not foundforcegc: phase errorgopa" ascii
      $s9 = "pg on g0bad TinySizeClassg already scannedmark - bad statusscanobject n == 0swept cached spanmarkBits overflowRtlGetCurrentPeb" fullword ascii
      $s10 = "mheap.freeSpanLocked - invalid free of user arena chunkcasfrom_Gscanstatus:top gp->status is not in scan state is currently not " ascii
      $s11 = "runtime/rwmutex.go" fullword ascii
      $s12 = "runtime/internal/atomic.(*Pointer[go.shape.struct { runtime.stack runtime.stack; runtime.stackguard0 uintptr; runtime.stackguard" ascii
      $s13 = "*runtime.mutex" fullword ascii
      $s14 = "floating point errorGC sweep terminationResetDebugLog (test)chan send (nil chan)malloc during signalclose of nil channelnotetsle" ascii
      $s15 = "d errorrunlock of unlocked rwmutexsigsend: inconsistent statemakeslice: len out of rangemakeslice: cap out of rangegrowslice: le" ascii
      $s16 = "all goroutines stack tracenotewakeup - double wakeuppersistentalloc: size == 0/gc/cycles/total:gc-cyclesnegative idle mark worke" ascii
      $s17 = "IIIIIIIIIII" fullword wide /* reversed goodware string 'IIIIIIIIIII' */
      $s18 = "ABCDEFGHIJ" fullword wide /* reversed goodware string 'JIHGFEDCBA' */
      $s19 = "runtime.errorAddressString.Error" fullword ascii
      $s20 = "runqhead" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 24000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}
