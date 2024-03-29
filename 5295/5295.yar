/* 
   YARA Rule Set 
   Author: The DFIR Report 
   Date: 2021-10-31 
   Identifier: Case 5295 From Zero to Domain Admin
   Reference: https://thedfirreport.com/2021/11/01/from-zero-to-domain-admin/ 

*/ 



/* Rule Set ----------------------------------------------------------------- */ 

rule __case_5295_1407 { 
   meta: 
      description = "5295 - file 1407.bin" 
      author = "The DFIR Report" 
      reference = "https://thedfirreport.com" 
      date = "2021-08-12" 
      hash1 = "45910874dfe1a9c3c2306dd30ce922c46985f3b37a44cb14064a963e1244a726" 
   strings: 
      $s1 = "zG<<&Sa" fullword ascii 
      $s2 = "r@TOAa" fullword ascii 
      $s3 = "DTjt{R" fullword ascii 
   condition: 
      uint16(0) == 0xa880 and filesize < 2KB and 
      all of them 
} 



rule _case_5295_sig_7jkio8943wk { 
   meta: 
      description = "5295 - file 7jkio8943wk.exe" 
      author = "The DFIR Report" 
      reference = "https://thedfirreport.com" 
      date = "2021-08-12" 
      hash1 = "dee4bb7d46bbbec6c01dc41349cb8826b27be9a0dcf39816ca8bd6e0a39c2019" 
   strings: 
      $s1 = " (os error other os erroroperation interruptedwrite zerotimed outinvalid datainvalid input parameteroperation would blockentity " ascii 
      $s2 = "already existsbroken pipeaddress not availableaddress in usenot connectedconnection abortedconnection resetconnection refusedper" ascii 
      $s3 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii 
      $s4 = "UnexpectedEofNotFoundPermissionDeniedConnectionRefusedConnectionResetConnectionAbortedNotConnectedAddrInUseAddrNotAvailableBroke" ascii 
      $s5 = "nPipeAlreadyExistsWouldBlockInvalidInputInvalidDataTimedOutWriteZeroInterruptedOtherN" fullword ascii 
      $s6 = "failed to fill whole buffercould not resolve to any addresses" fullword ascii 
      $s7 = " (os error other os erroroperation interruptedwrite zerotimed outinvalid datainvalid input parameteroperation would blockentity " ascii 
      $s8 = "mission deniedentity not foundunexpected end of fileGetSystemTimePreciseAsFileTime" fullword ascii 
      $s9 = "invalid socket addressinvalid port valuestrings passed to WinAPI cannot contain NULsinvalid utf-8: corrupt contentsinvalid utf-8" ascii 
      $s10 = "invalid socket addressinvalid port valuestrings passed to WinAPI cannot contain NULsinvalid utf-8: corrupt contentsinvalid utf-8" ascii 
      $s11 = "\\data provided contains a nul byteSleepConditionVariableSRWkernel32ReleaseSRWLockExclusiveAcquireSRWLockExclusive" fullword ascii 
      $s12 = "fatal runtime error: " fullword ascii 
      $s13 = "assertion failed: key != 0WakeConditionVariable" fullword ascii 
      $s14 = "kindmessage" fullword ascii 
      $s15 = "0x000102030405060708091011121314151617181920212223242526272829303132333435363738394041424344454647484950515253545556575859606162" ascii 
      $s16 = "..\\\\?\\.\\UNC\\Windows stdio in console mode does not support writing non-UTF-8 byte sequences" fullword ascii 
      $s17 = "OS Error  (FormatMessageW() returned invalid UTF-16) (FormatMessageW() returned error )formatter error" fullword ascii 
      $s18 = "FromUtf8Errorbytes" fullword ascii 
      $s19 = "  VirtualProtect failed with code 0x%x" fullword ascii 
      $s20 = "invalid utf-8 sequence of  bytes from index incomplete utf-8 byte sequence from index " fullword ascii 
   condition: 
      uint16(0) == 0x5a4d and filesize < 800KB and 
      8 of them 
} 


rule __case_5295_check { 
   meta: 
      description = "5295 - file check.exe" 
      author = "The DFIR Report" 
      reference = "https://thedfirreport.com" 
      date = "2021-08-12" 
      hash1 = "c443df1ddf8fd8a47af6fbfd0b597c4eb30d82efd1941692ba9bb9c4d6874e14" 
   strings: 
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii 
      $s2 = "F:\\Source\\WorkNew18\\CheckOnline\\Release\\CheckOnline.pdb" fullword ascii 
      $s3 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii 
      $s4 = " Type Descriptor'" fullword ascii 
      $s5 = "operator co_await" fullword ascii 
      $s6 = "operator<=>" fullword ascii 
      $s7 = ".data$rs" fullword ascii 
      $s8 = "File opening error: " fullword ascii 
      $s9 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii 
      $s10 = ":0:8:L:\\:h:" fullword ascii 
      $s11 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide 
      $s12 = " Base Class Descriptor at (" fullword ascii 
      $s13 = " Class Hierarchy Descriptor'" fullword ascii 
      $s14 = " Complete Object Locator'" fullword ascii 
      $s15 = "network reset" fullword ascii /* Goodware String - occured 567 times */ 
      $s16 = "connection already in progress" fullword ascii /* Goodware String - occured 567 times */ 
      $s17 = "wrong protocol type" fullword ascii /* Goodware String - occured 567 times */ 
      $s18 = "network down" fullword ascii /* Goodware String - occured 567 times */ 
      $s19 = "owner dead" fullword ascii /* Goodware String - occured 567 times */ 
      $s20 = "protocol not supported" fullword ascii /* Goodware String - occured 568 times */ 
   condition: 
      uint16(0) == 0x5a4d and filesize < 500KB and 
      all of them 
} 


rule __case_5295_zero { 
   meta: 
      description = "5295 - file zero.exe" 
      author = "The DFIR Report" 
      reference = "https://thedfirreport.com" 
      date = "2021-08-12" 
      hash1 = "3a8b7c1fe9bd9451c0a51e4122605efc98e7e4e13ed117139a13e4749e211ed0" 
   strings: 
      $x1 = "powershell.exe -c Reset-ComputerMachinePassword" fullword wide 
      $s2 = "COMMAND - command that will be executed on domain controller. should be surrounded by quotes" fullword ascii 
      $s3 = "ZERO.EXE IP DC DOMAIN ADMIN_USERNAME [-c] COMMAND :" fullword ascii 
      $s4 = "-c - optional, use it when command is not binary executable itself" fullword ascii 
      $s5 = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii 
      $s6 = "C:\\p\\Release\\zero.pdb" fullword ascii 
      $s7 = "+command executed" fullword ascii 
      $s8 = "COMMAND - %ws" fullword ascii 
      $s9 = "rpc_drsr_ProcessGetNCChangesReply" fullword wide 
      $s10 = "ZERO.EXE -test IP DC" fullword ascii 
      $s11 = "to test if the target is vulnurable only" fullword ascii 
      $s12 = "IP - ip address of domain controller" fullword ascii 
      $s13 = "ADMIN_USERNAME - %ws" fullword ascii 
      $s14 = "error while parsing commandline. no command is found" fullword ascii 
      $s15 = "rpcbindingsetauthinfo fail" fullword ascii 
      $s16 = "x** SAM ACCOUNT **" fullword wide 
      $s17 = "%COMSPEC% /C " fullword wide 
      $s18 = "EXECUTED SUCCESSFULLY" fullword ascii 
      $s19 = "TARGET IS VULNURABLE" fullword ascii 
      $s20 = "have no admin rights on target, exiting" fullword ascii 
   condition: 
      uint16(0) == 0x5a4d and filesize < 500KB and 
      1 of ($x*) and 4 of them 
} 


rule __case_5295_GAS { 
   meta: 
      description = "5295 - file GAS.exe" 
      author = "The DFIR Report" 
      reference = "https://thedfirreport.com" 
      date = "2021-08-12" 
      hash1 = "be13b8457e7d7b3838788098a8c2b05f78506aa985e0319b588f01c39ca91844" 
   strings: 
      $s1 = "A privileged instruction was executed at address 0x00000000." fullword ascii 
      $s2 = "Stack dump (SS:ESP)" fullword ascii 
      $s3 = "!This is a Windows NT windowed executable" fullword ascii 
      $s4 = "An illegal instruction was executed at address 0x00000000." fullword ascii 
      $s5 = "ff.exe" fullword wide 
      $s6 = "Open Watcom C/C++32 Run-Time system. Portions Copyright (C) Sybase, Inc. 1988-2002." fullword ascii 
      $s7 = "openwatcom.org" fullword wide 
      $s8 = "Open Watcom Dialog Editor" fullword wide 
      $s9 = "A stack overflow was encountered at address 0x00000000." fullword ascii 
      $s10 = "A fatal error is occured" fullword ascii 
      $s11 = "An integer divide by zero was encountered at address 0x00000000." fullword ascii 
      $s12 = "address 0x00000000 and" fullword ascii 
      $s13 = "Open Watcom" fullword wide 
      $s14 = "The instruction at 0x00000000 caused an invalid operation floating point" fullword ascii 
      $s15 = "The instruction at 0x00000000 caused a denormal operand floating point" fullword ascii 
      $s16 = "`.idata" fullword ascii /* Goodware String - occured 1 times */ 
      $s17 = "xsJr~.~" fullword ascii 
      $s18 = "iJJW3We" fullword ascii 
      $s19 = "Rmih_O|" fullword ascii 
      $s20 = "The instruction at 0x00000000 referenced memory " fullword ascii 
   condition: 
      uint16(0) == 0x5a4d and filesize < 200KB and 
      all of them 
} 


rule __case_5295_agent1 { 
   meta: 
      description = "5295 - file agent1.ps1" 
      author = "The DFIR Report" 
      reference = "https://thedfirreport.com" 
      date = "2021-08-12" 
      hash1 = "94dcca901155119edfcee23a50eca557a0c6cbe12056d726e9f67e3a0cd13d51" 
   strings: 
      $s1 = "[Byte[]]$oBUEFlUjsZVVaEBHhsKWa = [System.Convert]::FromBase64String((-join($gDAgdPFzzxgYnLNNHSSMR,'zzkKItFCIsIUejI/P//g8QMi1UIiU" ascii 
      $s2 = "ap0cqOwB7hW5z/yOlqICYNrdwqfvCvWSqWbfs/NWgxfvurRRLs7xIQrzXCCgwqMnhB154e8iubTSzAhliQfIRC1djlZTGXO4nBUD68VD/Zmo81DI9wVoQ2++AOz+IT3x" ascii 
      $s3 = "[Runtime.InteropServices.Marshal]::Copy($oBUEFlUjsZVVaEBHhsKWa,(2372 - 2372),$CjHxQlvEzGUrZUarFZbrz,$oBUEFlUjsZVVaEBHhsKWa.Lengt" ascii 
      $s4 = "[Runtime.InteropServices.Marshal]::Copy($oBUEFlUjsZVVaEBHhsKWa,(2372 - 2372),$CjHxQlvEzGUrZUarFZbrz,$oBUEFlUjsZVVaEBHhsKWa.Lengt" ascii 
      $s5 = "zSEEdr8FnfXshvasO1lodzp/T9fIQLBuz5baYtW7iK9lRAYZYDdQrnvpxmxJOxjuabTg5nBEWzTQSZaXmNRB2nSSK9/yfGeYecXO8FOXN8lEEE3BXhBrTFXDyXg1BiJb" ascii 
      $s6 = "eQvmMAIAnreX2We51OWxYt5ykA3Z9w9FN3hFaSuBjn2u6kwODP+r2Wv2ruryjIa0nyZxgwUCBotpX5U/k9jDsDgC9YyR1gvyD6r268nAnvMP09U+KvTM/AZhx/mFtget" ascii 
      $s7 = "3H2+O+/8sPyM9FWRrXUO/9a4LwBKmuv8Qsh/50l6VnyQGICZ8PuITwgJxzV37f/NZJqTrvQa70A0mf6hKrjuUSfulv/uUgYZmSdLPugLfe9WK9VenoTnKUT/ir/GHATM" ascii 
      $s8 = "sQroZ/z//wNF8BNV9IlF8IlV9ItF8ItV9LEG6G78//8zRfAzVfSJRfCJVfTpdP///4tF8ItV9LED6DD8//8DRfATVfSJRfCJVfSLRfCLVfSxC+g3/P//M0XwM1X0iUXw" ascii 
      $s9 = "a2cxwtfBqoUe4/erpeTB7XIYMFFtX23EEnTdPQbUXCd5O9j5mAeVZpRNWF9tvvy2+qlNieD1WlTj2fUZaiYPrpkKd7DllqHRkAbblgRp0IJO4yiFrd/xaGy8NiPtThnO" ascii 
      $s10 = "j+XqDEzWEbsdht2FdZc1j2/fJoIugVtps/bH7uP1dq8FA6+GVzpw0UN42KgXL9sMYAnJRJj6gpW7oZ1fGv4b+d2xjo8yQM798A3UWadQSGbnsmzV+2k/KmfqAlvYqIrC" ascii 
      $s11 = "ZQ0NlAxyJeQHiqm9NZr4Xjh9V25TXa0vWwb/yXI+IL59EdsKDkehBeuasslnEdfgAq7j+mEp0C70K+oeKHZwHnV9/fa4H93lInRTqutejUqOXfJN0Sqa0gkjX5lJvIzT" ascii 
      $s12 = "T/vbRvTMv6ePKoOS5EUjzgqjY7QZsueNgGEt1KTiP5R9zOnabhD20lmwcjl6vSapoMgKyS57Oqv0rZHShi+XWdJtmFgsRJYHLQcuMbqAmVRLb9GpaVkJl0fC2X+87Lup" ascii 
      $s13 = "$vpFhaWLTcsrOHCQLzsEzN = 'mbFPGDtpJicxXcdFG/Ydmz4dHGi5llA0tRmH2WwVJpYbsfxCiAfFy0kckQnw6EeyeH40K0H6hmZ/H4KpB3tbTVXrd6LvKnUmzVJ8eg" ascii 
      $s14 = "$nkRLOujTuMsDDaMxkgFbp = [OkwgNsSnFFEmvLpdsdISG]::CreateThread(($ZCHhKqfmmzVFPUgdkjqZk),(-6012 + 6012),$CjHxQlvEzGUrZUarFZbrz,(3" ascii 
      $s15 = "guQh6vh+8CQHOjfK/YMdwFr1UGqkMdLfobM5WYeyHvTezZttJ+hfHIT795hhejCINf/0AzPrunDuwun7kZ2ueDpJxwEfcqtHkvmt4qhgcGu0UuebvxPgjnrZQ3i7OWiG" ascii 
      $s16 = "+SvFBrG7BgR5cmdbbRuoy7ewt2CJqeJXmYVV3b1tf+Rw1xb1P6vNtyobWpXNYfVu9TAVUcxKXQxoOTum5J4q6E7iTyIltAmiRnxUxTlQwjjhwOfYdYviZSKlKJ32tl2x" ascii 
      $s17 = "    [DllImport(\"kernel32.dll\")]" fullword ascii 
      $s18 = "/v0KltMpb69/8jsWR23PkNuPrK3FXehCwqN1FYNCGR+tbLJ4oEzVw/sOoCrrK91sAjUs1yNKhJXRjJ4Td/AAB+51bVz1CMXtUzaZ80eDvILBw4eMSltg04/7XSRV3O5B" ascii 
      $s19 = "$wLHiDWZiDeApQYLEVCjxX = (([regex]::Matches('qisBjSUmAFJ0IqAT3R+byDBdA3K6vHNI//aNbyh+ZYFOREbwR+QFlGQ3OUlMZO4EkPJppVBn3syXugkbjkn" ascii 
      $s20 = "M9KA4R/T6MMzwDPSw8xVi+yD7AiLRQiJRfiLTRCJTfyLVRCD6gGJVRCDffwAdB6LRQiLTQyKEYgQi0UIg8ABiUUIi00Mg8EBiU0M682LRfiL5V3DzMzMzMzMzMzMzFWL" ascii 
   condition: 
      uint16(0) == 0x6441 and filesize < 100KB and 
      8 of them 
} 
